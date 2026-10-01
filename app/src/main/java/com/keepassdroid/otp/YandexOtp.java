/*
 * Copyright 2025 KeePassDroid contributors.
 *
 * This file is part of KeePassDroid.
 *
 * KeePassDroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * KeePassDroid is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeePassDroid.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.keepassdroid.otp;

import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Yandex 2FA ("YaOTP") support. Ported from KeeYaOtp / KeePassOTP.
 */
final class YandexOtp {

    public static final int MIN_PIN_LENGTH = 4;
    public static final int MAX_PIN_LENGTH = 16;

    private static final int TIME_PERIOD_SEC = 30;
    private static final int OTP_LENGTH = 8;

    private YandexOtp() {
    }

    static boolean isValidPin(String pin) {
        if (pin == null || pin.length() < MIN_PIN_LENGTH || pin.length() > MAX_PIN_LENGTH) {
            return false;
        }
        for (int i = 0; i < pin.length(); i++) {
            char c = pin.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    /** Decode and validate a Yandex secret. Returns the 16 byte key or null. */
    static byte[] secretKey(String base32Seed) {
        byte[] decoded;
        try {
            decoded = OtpCodec.base32Decode(base32Seed);
        } catch (RuntimeException e) {
            return null;
        }
        if (decoded.length < 26 || !checksumIsValid(decoded)) {
            return null;
        }
        byte[] data = new byte[16];
        int offset = decoded.length - 26;
        System.arraycopy(decoded, offset, data, 0, 16);
        return data;
    }

    static byte[] secretKey(String base32Seed, String pin) {
        byte[] data = secretKey(base32Seed);
        if (data == null) {
            return null;
        }
        if (!isValidPin(pin)) {
            return null;
        }
        int pinLength = (decodedPinLength(base32Seed));
        if (pinLength == pin.length()) {
            return data;
        }
        return null;
    }

    static int decodedPinLength(String base32Seed) {
        byte[] decoded;
        try {
            decoded = OtpCodec.base32Decode(base32Seed);
        } catch (RuntimeException e) {
            return -1;
        }
        if (decoded.length < 26 || !checksumIsValid(decoded)) {
            return -1;
        }
        return ((decoded[decoded.length - 2] & 0xFF) >> 4) + 1;
    }

    static String generate(String base32Seed, String pin, long utcSeconds) {
        byte[] secret = secretKey(base32Seed, pin);
        if (secret == null) {
            return null;
        }
        return generate(secret, pin, utcSeconds);
    }

    private static String generate(byte[] secret, String pin, long utcSeconds) {
        byte[] pinBytes = OtpCodec.utf8Encode(pin);
        byte[] key = new byte[pinBytes.length + secret.length];
        System.arraycopy(pinBytes, 0, key, 0, pinBytes.length);
        System.arraycopy(secret, 0, key, pinBytes.length, secret.length);

        byte[] keyHash;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            keyHash = sha256.digest(key);
        } catch (Exception e) {
            return null;
        }
        if (keyHash.length > 1 && keyHash[0] == 0) {
            byte[] temp = new byte[keyHash.length - 1];
            System.arraycopy(keyHash, 1, temp, 0, temp.length);
            keyHash = temp;
        }

        long period = utcSeconds / TIME_PERIOD_SEC;
        byte[] periodBytes = new byte[8];
        for (int i = 7; i >= 0; i--) {
            periodBytes[i] = (byte) (period & 0xFF);
            period >>= 8;
        }

        byte[] hash;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keyHash, "HmacSHA256"));
            hash = mac.doFinal(periodBytes);
        } catch (Exception e) {
            return null;
        }

        int offset = hash[hash.length - 1] & 0x0F;
        long slice = 0;
        for (int i = offset; i < offset + 8; i++) {
            slice = (slice << 8) | (hash[i] & 0xFF);
        }
        slice &= Long.MAX_VALUE;

        long limit = 1;
        for (int i = 0; i < OTP_LENGTH; i++) {
            limit *= 26;
        }

        return toBase26(slice % limit, OTP_LENGTH);
    }

    private static String toBase26(long value, int length) {
        char[] chars = new char[length];
        for (int i = length - 1; i >= 0; i--) {
            chars[i] = (char) ('a' + (value % 26));
            value /= 26;
        }
        return new String(chars);
    }

    private static int numberOfLeadingZeros16(int value) {
        return Integer.numberOfLeadingZeros(value) - 16;
    }

    private static boolean checksumIsValid(byte[] input) {
        if (input.length < 4) {
            return false;
        }

        final int poly = 6387;
        int checksumOrig = ((input[input.length - 2] & 0x0F) << 8)
                | (input[input.length - 1] & 0xFF);

        int accum = 0;
        int accumBits = 0;
        int inputTotalBitsAvailable = input.length * 8 - 12;
        int inputIndex = 0;
        int inputBitsAvailable = 8;

        while (inputTotalBitsAvailable > 0) {
            int requiredBits = 13 - accumBits;
            if (inputTotalBitsAvailable < requiredBits) {
                requiredBits = inputTotalBitsAvailable;
            }
            while (requiredBits > 0) {
                int curInput = input[inputIndex] & ((1 << inputBitsAvailable) - 1);
                int bitsToRead = Math.min(requiredBits, inputBitsAvailable);
                curInput >>= inputBitsAvailable - bitsToRead;
                accum = ((accum << bitsToRead) | curInput) & 0xFFFF;

                inputTotalBitsAvailable -= bitsToRead;
                requiredBits -= bitsToRead;
                inputBitsAvailable -= bitsToRead;
                accumBits += bitsToRead;
                if (inputBitsAvailable == 0) {
                    inputIndex++;
                    inputBitsAvailable = 8;
                }
            }
            if (accumBits == 13) {
                accum ^= poly;
            }
            accumBits = 16 - numberOfLeadingZeros16(accum);
        }

        return accum == checksumOrig;
    }
}
