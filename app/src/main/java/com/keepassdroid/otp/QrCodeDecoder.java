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

import android.content.ContentResolver;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Decodes QR codes (and other barcodes) from bitmaps using ZXing.
 */
public final class QrCodeDecoder {

    private static final int DEFAULT_MAX_DIMENSION = 1600;

    private QrCodeDecoder() {
    }

    /**
     * Attempt to decode a barcode from a bitmap. Returns the decoded text or {@code null}.
     */
    public static String decode(Bitmap bitmap) {
        if (bitmap == null) {
            return null;
        }
        int width = bitmap.getWidth();
        int height = bitmap.getHeight();
        if (width <= 0 || height <= 0) {
            return null;
        }

        int[] pixels = new int[width * height];
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height);

        RGBLuminanceSource source = new RGBLuminanceSource(width, height, pixels);
        BinaryBitmap binary = new BinaryBitmap(new HybridBinarizer(source));

        Map<DecodeHintType, Object> hints = new EnumMap<DecodeHintType, Object>(DecodeHintType.class);
        List<BarcodeFormat> formats = new ArrayList<BarcodeFormat>();
        formats.add(BarcodeFormat.QR_CODE);
        hints.put(DecodeHintType.POSSIBLE_FORMATS, formats);
        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);

        try {
            Result result = new MultiFormatReader().decode(binary, hints);
            return result == null ? null : result.getText();
        } catch (NotFoundException e) {
            return null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Load a bitmap from a content URI, downsampling large images so that decoding stays fast.
     */
    public static Bitmap loadBitmap(ContentResolver resolver, Uri uri) throws IOException {
        return loadBitmap(resolver, uri, DEFAULT_MAX_DIMENSION);
    }

    public static Bitmap loadBitmap(ContentResolver resolver, Uri uri, int maxDimension)
            throws IOException {
        if (resolver == null || uri == null) {
            return null;
        }

        BitmapFactory.Options bounds = new BitmapFactory.Options();
        bounds.inJustDecodeBounds = true;
        InputStream in = resolver.openInputStream(uri);
        if (in == null) {
            return null;
        }
        try {
            BitmapFactory.decodeStream(in, null, bounds);
        } finally {
            closeQuietly(in);
        }

        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
            return null;
        }

        int sample = 1;
        int largest = Math.max(bounds.outWidth, bounds.outHeight);
        while (maxDimension > 0 && largest / sample > maxDimension) {
            sample *= 2;
        }

        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inSampleSize = sample;

        in = resolver.openInputStream(uri);
        if (in == null) {
            return null;
        }
        try {
            return BitmapFactory.decodeStream(in, null, options);
        } finally {
            closeQuietly(in);
        }
    }

    private static void closeQuietly(InputStream in) {
        if (in != null) {
            try {
                in.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }
}
