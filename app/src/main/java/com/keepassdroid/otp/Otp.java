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

import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Core one time password implementation. This is a Java port of the {@code KPOTP} class from the
 * KeePassOTP plugin (https://github.com/Rookiestyle/KeePassOTP) so that KeePassDroid can read,
 * generate and write exactly the same {@code otp} entry strings.
 */
public class Otp {

    /** Entry string field used by the KeePassOTP plugin to store the OTP configuration. */
    public static final String FIELD = "otp";

    /** Number of seconds before expiry at which the remaining time is displayed. */
    public static final int TOTP_SOON_EXPIRING = 5;

    public enum Type {
        HOTP, TOTP, STEAM, YANDEX
    }

    public enum Hash {
        SHA1, SHA256, SHA512
    }

    public enum Encoding {
        BASE32, BASE64, HEX, UTF8
    }

    private static final char[] STEAM_CHARS = new char[] {
            '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K',
            'M', 'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y' };

    private Type type = Type.TOTP;
    private Hash hash = Hash.SHA1;
    private Encoding encoding = Encoding.BASE32;
    private int length = 6;
    private int timeStep = 30;
    private int counter = 0;
    private String yandexPin = "";
    private String seed = "";
    private byte[] key;
    private String issuer = "";
    private String label = "";
    private boolean valid = false;

    public Otp() {
    }

    // ---------------------------------------------------------------------------------------------
    // Parsing / construction
    // ---------------------------------------------------------------------------------------------

    /**
     * Parse an {@code otpauth://} URI. Returns {@code null} when the string is not an otpauth URI
     * or when it does not contain a secret.
     */
    public static Otp parse(String otpauth) {
        if (otpauth == null) {
            return null;
        }
        String value = otpauth.trim();
        if (value.isEmpty() || !value.regionMatches(true, 0, "otpauth://", 0, 10)) {
            return null;
        }

        String rest = value.substring(10);
        int queryStart = rest.indexOf('?');
        String path = queryStart >= 0 ? rest.substring(0, queryStart) : rest;
        String query = queryStart >= 0 ? rest.substring(queryStart + 1) : "";

        int slash = path.indexOf('/');
        String host = slash >= 0 ? path.substring(0, slash) : path;
        String labelPart = slash >= 0 ? path.substring(slash + 1) : "";

        Map<String, String> params = new HashMap<String, String>();
        String secret = parseQuery(query, params);
        if (secret == null || secret.isEmpty()) {
            return null;
        }

        Otp otp = new Otp();
        otp.type = "hotp".equalsIgnoreCase(host) ? Type.HOTP : Type.TOTP;

        if (!labelPart.isEmpty()) {
            int colon = labelPart.indexOf(':');
            if (colon >= 0) {
                otp.issuer = decode(labelPart.substring(0, colon)).replace("/", "");
                otp.label = decode(labelPart.substring(colon + 1)).replace("/", "");
            } else {
                otp.label = decode(labelPart).replace("/", "");
            }
        }

        String algorithm = params.get("algorithm");
        if (algorithm != null) {
            algorithm = algorithm.toLowerCase(Locale.US);
            if ("sha256".equals(algorithm)) {
                otp.hash = Hash.SHA256;
            } else if ("sha512".equals(algorithm)) {
                otp.hash = Hash.SHA512;
            } else {
                otp.hash = Hash.SHA1;
            }
        }

        String digits = params.get("digits");
        if (digits != null) {
            try {
                otp.length = Integer.parseInt(digits.trim());
            } catch (NumberFormatException e) {
                otp.length = 6;
            }
        }

        String encoding = params.get("encoding");
        if (encoding != null) {
            encoding = encoding.toLowerCase(Locale.US);
            if ("base64".equals(encoding)) {
                otp.encoding = Encoding.BASE64;
            } else if ("hex".equals(encoding)) {
                otp.encoding = Encoding.HEX;
            } else if ("utf8".equals(encoding)) {
                otp.encoding = Encoding.UTF8;
            } else {
                otp.encoding = Encoding.BASE32;
            }
        }

        String encoder = params.get("encoder");
        if (encoder != null) {
            try {
                otp.type = Type.valueOf(encoder.toUpperCase(Locale.US));
            } catch (IllegalArgumentException e) {
                // keep the type derived from the URI host
            }
        }

        if (otp.type == Type.HOTP) {
            String counter = params.get("counter");
            if (counter != null) {
                try {
                    otp.counter = Math.max(0, Integer.parseInt(counter.trim()));
                } catch (NumberFormatException e) {
                    otp.counter = 0;
                }
            }
        } else {
            String period = params.get("period");
            if (period != null) {
                try {
                    otp.timeStep = Math.max(1, Integer.parseInt(period.trim()));
                } catch (NumberFormatException e) {
                    otp.timeStep = 30;
                }
            }
        }

        String issuer = params.get("issuer");
        if (issuer != null && !issuer.isEmpty()) {
            otp.issuer = issuer;
        }

        if (otp.type == Type.YANDEX) {
            String pin = params.get("yandexpin");
            otp.yandexPin = pin == null ? "" : pin;
        }

        otp.setSeed(trimTrailingPadding(secret));
        return otp;
    }

    /**
     * Build an OTP from a raw (non otpauth) seed and explicit settings.
     */
    public static Otp fromSeed(String seed, Type type, Hash hash, Encoding encoding, int length,
            int timeStep, int counter, String issuer, String label, String yandexPin) {
        Otp otp = new Otp();
        otp.hash = hash == null ? Hash.SHA1 : hash;
        otp.encoding = encoding == null ? Encoding.BASE32 : encoding;
        otp.type = type == null ? Type.TOTP : type;
        otp.issuer = issuer == null ? "" : issuer;
        otp.label = label == null ? "" : label;
        otp.yandexPin = yandexPin == null ? "" : yandexPin;
        otp.counter = Math.max(0, counter);
        otp.timeStep = Math.max(1, timeStep);
        if (otp.type == Type.STEAM) {
            otp.length = 5;
        } else {
            otp.length = Math.min(10, Math.max(length, 6));
        }
        otp.setSeed(seed);
        return otp;
    }

    private static String parseQuery(String query, Map<String, String> params) {
        String secret = null;
        if (query == null || query.isEmpty()) {
            return null;
        }
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String rawKey = eq >= 0 ? pair.substring(0, eq) : pair;
            String rawValue = eq >= 0 ? pair.substring(eq + 1) : "";
            String key = decode(rawKey).toLowerCase(Locale.US);
            if ("secret".equals(key)) {
                // The plugin reads the secret without URL decoding it.
                secret = rawValue;
            } else {
                params.put(key, decode(rawValue));
            }
        }
        return secret;
    }

    /** The plugin removes trailing {@code %3d} sequences from a URI secret. */
    private static String trimTrailingPadding(String seed) {
        String value = seed;
        int count = 0;
        while (value.length() >= 3) {
            int idx = value.length() - 3;
            if (value.charAt(idx) == '%' && value.charAt(idx + 1) == '3'
                    && (value.charAt(idx + 2) == 'd' || value.charAt(idx + 2) == 'D')) {
                count++;
                value = value.substring(0, idx);
            } else {
                break;
            }
        }
        return value;
    }

    private static String decode(String value) {
        if (value == null) {
            return "";
        }
        try {
            return URLDecoder.decode(value, "UTF-8");
        } catch (Exception e) {
            return value;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Seed / key handling
    // ---------------------------------------------------------------------------------------------

    private void setSeed(String value) {
        this.valid = false;
        this.key = null;
        this.seed = "";
        if (value == null) {
            return;
        }

        StringBuilder work = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ' ') {
                continue;
            }
            if (encoding == Encoding.BASE32) {
                if (c == '0') {
                    c = 'O';
                } else if (c == '1') {
                    c = 'L';
                } else if (c == '8') {
                    c = 'B';
                }
            }
            work.append(c);
        }
        this.seed = work.toString();

        if (type == Type.YANDEX) {
            this.valid = !seed.isEmpty() && YandexOtp.secretKey(seed) != null
                    && YandexOtp.isValidPin(yandexPin);
            return;
        }

        try {
            switch (encoding) {
                case BASE32:
                    key = OtpCodec.base32Decode(padTo(seed, 8));
                    break;
                case BASE64:
                    key = OtpCodec.base64Decode(padTo(seed, 8));
                    break;
                case HEX:
                    key = OtpCodec.hexDecode(seed);
                    break;
                case UTF8:
                default:
                    key = OtpCodec.utf8Encode(seed);
                    break;
            }
            this.valid = key != null && key.length > 0;
        } catch (RuntimeException e) {
            this.key = null;
            this.seed = "";
            this.valid = false;
        }
    }

    private static String padTo(String value, int multiple) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        int remainder = value.length() % multiple;
        if (remainder == 0) {
            return value;
        }
        StringBuilder sb = new StringBuilder(value);
        while (sb.length() % multiple != 0) {
            sb.append('=');
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------------------------------------
    // Generation
    // ---------------------------------------------------------------------------------------------

    private static long nowSeconds() {
        return System.currentTimeMillis() / 1000L;
    }

    public boolean isValid() {
        return valid;
    }

    public boolean hasSeed() {
        return seed != null && !seed.isEmpty();
    }

    public String getSeed() {
        return seed;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
        if (type == Type.STEAM) {
            this.length = 5;
        }
        if (hasSeed()) {
            setSeed(seed);
        }
    }

    public Hash getHash() {
        return hash;
    }

    public void setHash(Hash hash) {
        this.hash = hash;
    }

    public Encoding getEncoding() {
        return encoding;
    }

    public void setEncoding(Encoding encoding) {
        this.encoding = encoding;
        if (hasSeed()) {
            setSeed(seed);
        }
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        if (type == Type.STEAM) {
            this.length = 5;
        } else {
            this.length = Math.min(10, Math.max(length, 6));
        }
    }

    public int getTimeStep() {
        return timeStep;
    }

    public void setTimeStep(int timeStep) {
        this.timeStep = Math.max(1, timeStep);
    }

    public int getCounter() {
        return counter;
    }

    public void setCounter(int counter) {
        this.counter = Math.max(0, counter);
    }

    public String getYandexPin() {
        return yandexPin;
    }

    public void setYandexPin(String yandexPin) {
        this.yandexPin = yandexPin == null ? "" : yandexPin;
        if (hasSeed()) {
            setSeed(seed);
        }
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer == null ? "" : issuer;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label == null ? "" : label;
    }

    /** Generate the OTP for the current HOTP counter or the current wall clock time. */
    public String getOtp() {
        return getOtpAt(nowSeconds());
    }

    /** Generate the OTP at a fixed point in time (seconds since the UNIX epoch). */
    public String getOtpAt(long utcSeconds) {
        if (!valid) {
            return "";
        }
        if (type == Type.YANDEX) {
            String result = YandexOtp.generate(seed, yandexPin, utcSeconds);
            return result == null ? "" : result;
        }
        long value = (type == Type.HOTP) ? counter : (utcSeconds / timeStep);
        return generate(value);
    }

    /** Generate for an explicit HOTP counter / TOTP time step. */
    public String generate(long value) {
        if (!valid || type == Type.YANDEX) {
            return "";
        }
        byte[] data = otpData(value);
        byte[] mac = computeHash(data);
        if (mac == null || mac.length < 4) {
            return "";
        }
        int offset = mac[mac.length - 1] & 0x0F;
        int binary = ((mac[offset] & 0x7F) << 24)
                | ((mac[offset + 1] & 0xFF) << 16)
                | ((mac[offset + 2] & 0xFF) << 8)
                | (mac[offset + 3] & 0xFF);

        if (type == Type.STEAM) {
            return steamString(binary);
        }

        long modulus = 1;
        for (int i = 0; i < length; i++) {
            modulus *= 10;
        }
        long otp = (binary & 0xFFFFFFFFL) % modulus;
        StringBuilder sb = new StringBuilder();
        sb.append(otp);
        while (sb.length() < length) {
            sb.insert(0, '0');
        }
        return sb.toString();
    }

    public int getRemainingSeconds() {
        long elapsed = nowSeconds();
        return timeStep - (int) (elapsed % timeStep);
    }

    private static byte[] otpData(long value) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
        return result;
    }

    private byte[] computeHash(byte[] data) {
        String algorithm;
        switch (hash) {
            case SHA256:
                algorithm = "HmacSHA256";
                break;
            case SHA512:
                algorithm = "HmacSHA512";
                break;
            case SHA1:
            default:
                algorithm = "HmacSHA1";
                break;
        }
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    private String steamString(int binary) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(STEAM_CHARS[binary % STEAM_CHARS.length]);
            binary /= STEAM_CHARS.length;
        }
        return sb.toString();
    }

    /** Add the plugin's display space in the middle of a code. */
    public static String readable(String otp) {
        if (otp == null || otp.isEmpty()) {
            return "";
        }
        int split = (otp.length() + 1) / 2;
        return otp.substring(0, split) + " " + otp.substring(split);
    }

    // ---------------------------------------------------------------------------------------------
    // Serialization back to the plugin's otpauth format
    // ---------------------------------------------------------------------------------------------

    public String getOtpAuthString() {
        StringBuilder sb = new StringBuilder();
        sb.append("otpauth://").append(type == Type.HOTP ? "hotp" : "totp").append("/");
        if (!issuer.isEmpty() && !label.isEmpty()) {
            sb.append(encodePath(issuer)).append(':').append(encodePath(label));
        } else if (issuer.isEmpty()) {
            sb.append(encodePath(label));
        }
        sb.append("?secret=").append(seed);
        if (hash != Hash.SHA1) {
            sb.append("&algorithm=").append(hash.name());
        }
        if (length != 6) {
            sb.append("&digits=").append(length);
        }
        if (type == Type.TOTP && timeStep != 30) {
            sb.append("&period=").append(timeStep);
        }
        if (type == Type.HOTP) {
            sb.append("&counter=").append(counter);
        }
        if (encoding != Encoding.BASE32) {
            sb.append("&encoding=").append(encoding.name());
        }
        if (!issuer.isEmpty()) {
            sb.append("&issuer=").append(encodeQuery(issuer));
        }
        if (type == Type.STEAM) {
            sb.append("&encoder=steam");
        } else if (type == Type.YANDEX) {
            sb.append("&encoder=yandex&yandexpin=").append(encodeQuery(yandexPin));
        }
        return sb.toString();
    }

    private static String encodePath(String value) {
        return percentEncode(value);
    }

    private static String encodeQuery(String value) {
        return percentEncode(value);
    }

    private static String percentEncode(String value) {
        if (value == null) {
            return "";
        }
        byte[] bytes = OtpCodec.utf8Encode(value);
        StringBuilder sb = new StringBuilder(bytes.length);
        for (byte b : bytes) {
            int c = b & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '!' || c == '~' || c == '*'
                    || c == '\'' || c == '(' || c == ')') {
                sb.append((char) c);
            } else {
                sb.append('%');
                sb.append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xF, 16)));
                sb.append(Character.toUpperCase(Character.forDigit(c & 0xF, 16)));
            }
        }
        return sb.toString();
    }
}
