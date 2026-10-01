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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.keepassdroid.otp.Otp.Encoding;
import com.keepassdroid.otp.Otp.Hash;
import com.keepassdroid.otp.Otp.Type;

public class OtpTest {

    private static final String RFC_SECRET = "12345678901234567890";

    private static Otp hotp(String secret, Encoding encoding, int digits) {
        return Otp.fromSeed(secret, Type.HOTP, Hash.SHA1, encoding, digits, 30, 0, "", "", "");
    }

    private static Otp totp(String secret, Hash hash, int digits) {
        return Otp.fromSeed(secret, Type.TOTP, hash, Encoding.UTF8, digits, 30, 0, "", "", "");
    }

    @Test
    public void rfc4226HotpVectors() {
        String[] expected = {
                "755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489" };
        Otp otp = hotp(RFC_SECRET, Encoding.UTF8, 6);
        assertTrue(otp.isValid());
        for (int counter = 0; counter < expected.length; counter++) {
            otp.setCounter(counter);
            assertEquals("counter " + counter, expected[counter], otp.generate(counter));
        }
    }

    @Test
    public void base32SeedMatchesUtf8Seed() {
        Otp base32 = hotp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Encoding.BASE32, 6);
        assertTrue(base32.isValid());
        assertEquals("755224", base32.generate(0));
        assertEquals("287082", base32.generate(1));
    }

    @Test
    public void rfc6238TotpSha1Vectors() {
        Otp otp = totp(RFC_SECRET, Hash.SHA1, 8);
        assertTrue(otp.isValid());
        assertEquals("94287082", otp.getOtpAt(59));
        assertEquals("07081804", otp.getOtpAt(1111111109));
        assertEquals("14050471", otp.getOtpAt(1111111111));
        assertEquals("89005924", otp.getOtpAt(1234567890));
        assertEquals("69279037", otp.getOtpAt(2000000000));
        assertEquals("65353130", otp.getOtpAt(20000000000L));
    }

    @Test
    public void rfc6238TotpSha256Vectors() {
        Otp otp = Otp.fromSeed("12345678901234567890123456789012", Type.TOTP, Hash.SHA256,
                Encoding.UTF8, 8, 30, 0, "", "", "");
        assertTrue(otp.isValid());
        assertEquals("46119246", otp.getOtpAt(59));
        assertEquals("68084774", otp.getOtpAt(1111111109));
        assertEquals("67062674", otp.getOtpAt(1111111111));
        assertEquals("91819424", otp.getOtpAt(1234567890));
        assertEquals("90698825", otp.getOtpAt(2000000000));
        assertEquals("77737706", otp.getOtpAt(20000000000L));
    }

    @Test
    public void rfc6238TotpSha512Vectors() {
        Otp otp = Otp.fromSeed(
                "1234567890123456789012345678901234567890123456789012345678901234",
                Type.TOTP, Hash.SHA512, Encoding.UTF8, 8, 30, 0, "", "", "");
        assertTrue(otp.isValid());
        assertEquals("90693936", otp.getOtpAt(59));
        assertEquals("25091201", otp.getOtpAt(1111111109));
        assertEquals("99943326", otp.getOtpAt(1111111111));
        assertEquals("93441116", otp.getOtpAt(1234567890));
        assertEquals("38618901", otp.getOtpAt(2000000000));
        assertEquals("47863826", otp.getOtpAt(20000000000L));
    }

    @Test
    public void parseOtpauthUri() {
        Otp otp = Otp.parse(
                "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");
        assertNotNull(otp);
        assertTrue(otp.isValid());
        assertEquals("Example", otp.getIssuer());
        assertEquals("alice@google.com", otp.getLabel());
        assertEquals(Type.TOTP, otp.getType());
        assertEquals(Hash.SHA1, otp.getHash());
        assertEquals(6, otp.getLength());
    }

    @Test
    public void parseHonorsAlgorithmDigitsAndPeriod() {
        Otp otp = Otp.parse("otpauth://totp/ACME:Bob?secret=JBSWY3DPEHPK3PXP"
                + "&algorithm=SHA256&digits=8&period=60");
        assertNotNull(otp);
        assertEquals(Hash.SHA256, otp.getHash());
        assertEquals(8, otp.getLength());
        assertEquals(60, otp.getTimeStep());
    }

    @Test
    public void parseHotpCounter() {
        Otp otp = Otp.parse("otpauth://hotp/ACME:Bob?secret=JBSWY3DPEHPK3PXP&counter=42");
        assertNotNull(otp);
        assertEquals(Type.HOTP, otp.getType());
        assertEquals(42, otp.getCounter());
    }

    @Test
    public void parseRejectsPlainSeedAndMissingSecret() {
        assertNull(Otp.parse("JBSWY3DPEHPK3PXP"));
        assertNull(Otp.parse("otpauth://totp/ACME:Bob?issuer=ACME"));
        assertNull(Otp.parse(null));
    }

    @Test
    public void otpauthRoundTrip() {
        Otp original = Otp.fromSeed("JBSWY3DPEHPK3PXP", Type.TOTP, Hash.SHA512, Encoding.BASE32,
                8, 60, 0, "ACME Co", "bob@example.com", "");
        String serialized = original.getOtpAuthString();

        Otp parsed = Otp.parse(serialized);
        assertNotNull(parsed);
        assertEquals("ACME Co", parsed.getIssuer());
        assertEquals("bob@example.com", parsed.getLabel());
        assertEquals(Hash.SHA512, parsed.getHash());
        assertEquals(8, parsed.getLength());
        assertEquals(60, parsed.getTimeStep());
        assertEquals(original.getOtpAt(1234567890), parsed.getOtpAt(1234567890));
    }

    @Test
    public void steamCodesUseSteamAlphabet() {
        Otp otp = Otp.fromSeed("JBSWY3DPEHPK3PXP", Type.STEAM, Hash.SHA1, Encoding.BASE32, 6, 30,
                0, "", "", "");
        assertTrue(otp.isValid());
        assertEquals(5, otp.getLength());
        String code = otp.getOtpAt(1234567890);
        assertEquals(5, code.length());
        for (char c : code.toCharArray()) {
            assertTrue("unexpected steam char " + c, "23456789BCDFGHJKMNPQRTVWXY".indexOf(c) >= 0);
        }
    }

    @Test
    public void readableSplitsCodeInHalf() {
        assertEquals("123 456", Otp.readable("123456"));
        assertEquals("1234 5678", Otp.readable("12345678"));
        assertEquals("", Otp.readable(""));
    }

    @Test
    public void seedSanitizationFixesCommonBase32Typos() {
        // 0 -> O, 1 -> L, 8 -> B and spaces are removed for base32 seeds.
        Otp otp = Otp.fromSeed("JB SW Y3 DP EHP K3 PXP 0 1 8", Type.TOTP, Hash.SHA1,
                Encoding.BASE32, 6, 30, 0, "", "", "");
        assertEquals("JBSWY3DPEHPK3PXPOLB", otp.getSeed());
    }

    @Test
    public void base32SeedWithUrlEncodedPaddingParses() {
        Otp expected = Otp.fromSeed("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Type.HOTP, Hash.SHA1,
                Encoding.BASE32, 6, 30, 0, "", "", "");
        Otp padded = Otp.parse("otpauth://hotp/X?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                + "%3D%3D%3D%3D");
        assertNotNull(padded);
        assertEquals(expected.generate(0), padded.generate(0));
        assertEquals(expected.generate(1), padded.generate(1));
    }

    @Test
    public void hexEncodedSeedParses() {
        Otp otp = Otp.fromSeed("3132333435363738393031323334353637383930", Type.HOTP, Hash.SHA1,
                Encoding.HEX, 6, 30, 0, "", "", "");
        assertTrue(otp.isValid());
        assertEquals("755224", otp.generate(0));
    }

    @Test
    public void hotpFromOtpauthUri() {
        Otp otp = Otp.parse("otpauth://hotp/Test:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                + "&counter=0");
        assertNotNull(otp);
        assertTrue(otp.isValid());
        assertEquals("755224", otp.generate(otp.getCounter()));
    }
}
