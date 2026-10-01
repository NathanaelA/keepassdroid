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

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;

/**
 * Small self contained decoders for the encodings used by the KeePassOTP plugin.
 *
 * These are deliberately implemented without {@code android.util.Base64} so that the OTP
 * calculation can be unit tested on a plain JVM and used on every supported API level.
 */
final class OtpCodec {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private OtpCodec() {
    }

    /**
     * Decode an RFC 4648 base32 string. Padding and whitespace are ignored and lower case
     * input is accepted. The alphabet matches the one used by KeePassLib and the plugin.
     */
    static byte[] base32Decode(String input) {
        if (input == null) {
            return new byte[0];
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-') {
                continue;
            }
            int value = BASE32_ALPHABET.indexOf(Character.toUpperCase(c));
            if (value < 0) {
                throw new IllegalArgumentException("Invalid base32 character: " + c);
            }
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                out.write((buffer >> bitsLeft) & 0xFF);
            }
        }

        return out.toByteArray();
    }

    /** Decode a base64 string, ignoring padding and whitespace. */
    static byte[] base64Decode(String input) {
        if (input == null) {
            return new byte[0];
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                continue;
            }
            int value;
            if (c >= 'A' && c <= 'Z') {
                value = c - 'A';
            } else if (c >= 'a' && c <= 'z') {
                value = c - 'a' + 26;
            } else if (c >= '0' && c <= '9') {
                value = c - '0' + 52;
            } else if (c == '+') {
                value = 62;
            } else if (c == '/') {
                value = 63;
            } else {
                throw new IllegalArgumentException("Invalid base64 character: " + c);
            }
            buffer = (buffer << 6) | value;
            bitsLeft += 6;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                out.write((buffer >> bitsLeft) & 0xFF);
            }
        }

        return out.toByteArray();
    }

    /** Decode a hexadecimal string. */
    static byte[] hexDecode(String input) {
        if (input == null) {
            return new byte[0];
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int high = -1;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int value = Character.digit(c, 16);
            if (value < 0) {
                continue;
            }
            if (high < 0) {
                high = value;
            } else {
                out.write((high << 4) | value);
                high = -1;
            }
        }

        return out.toByteArray();
    }

    static byte[] utf8Encode(String input) {
        return input == null ? new byte[0] : input.getBytes(UTF8);
    }
}
