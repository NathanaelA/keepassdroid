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
package com.keepassdroid;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.provider.MediaStore;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Base64;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.widget.Toolbar;
import androidx.core.content.FileProvider;

import com.android.keepass.R;
import com.keepassdroid.otp.Otp;
import com.keepassdroid.otp.QrCodeDecoder;

/**
 * Activity to add, edit or remove the OTP configuration of an entry.
 *
 * The result is returned as the {@code otp} entry string in the plugin's {@code otpauth://}
 * format (see {@link Otp#getOtpAuthString()}).
 */
public class OtpSetupActivity extends LockCloseHideActivity {

    public static final String EXTRA_OTP_URI = "otp_uri";
    public static final String EXTRA_OTP_RESULT = "otp_result";
    public static final String EXTRA_OTP_REMOVE = "otp_remove";

    private static final int REQUEST_CAMERA = 0x0F00;

    private static final String[] TYPE_LABELS = { "HOTP", "TOTP", "Steam", "Yandex" };
    private static final String[] HASH_LABELS = { "SHA1", "SHA256", "SHA512" };
    private static final String[] ENCODING_LABELS = { "BASE32", "BASE64", "HEX", "UTF8" };

    private EditText seedText;
    private EditText digitsText;
    private EditText periodText;
    private EditText counterText;
    private EditText pinText;
    private EditText issuerText;
    private EditText labelText;
    private Spinner typeSpinner;
    private Spinner hashSpinner;
    private Spinner encodingSpinner;
    private TextView previewText;

    private Uri cameraOutputUri;
    private File cameraOutputFile;
    private boolean updating;

    private final Handler handler = new Handler();
    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            updatePreview();
            handler.postDelayed(this, 1000);
        }
    };

    public static void Launch(Activity act, String otpUri, int requestCode) {
        Intent intent = new Intent(act, OtpSetupActivity.class);
        if (otpUri != null) {
            intent.putExtra(EXTRA_OTP_URI, otpUri);
        }
        act.startActivityForResult(intent, requestCode);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.otp_setup);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.otp_setup_title);
        }

        seedText = findViewById(R.id.otp_seed);
        digitsText = findViewById(R.id.otp_digits);
        periodText = findViewById(R.id.otp_period);
        counterText = findViewById(R.id.otp_counter);
        pinText = findViewById(R.id.otp_pin);
        issuerText = findViewById(R.id.otp_issuer);
        labelText = findViewById(R.id.otp_label);
        typeSpinner = findViewById(R.id.otp_type);
        hashSpinner = findViewById(R.id.otp_hash);
        encodingSpinner = findViewById(R.id.otp_encoding);
        previewText = findViewById(R.id.otp_preview);

        setupSpinner(typeSpinner, TYPE_LABELS);
        setupSpinner(hashSpinner, HASH_LABELS);
        setupSpinner(encodingSpinner, ENCODING_LABELS);

        TextWatcher watcher = new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                updatePreview();
            }
        };
        seedText.addTextChangedListener(watcher);
        digitsText.addTextChangedListener(watcher);
        periodText.addTextChangedListener(watcher);
        counterText.addTextChangedListener(watcher);
        pinText.addTextChangedListener(watcher);
        issuerText.addTextChangedListener(watcher);
        labelText.addTextChangedListener(watcher);

        AdapterView.OnItemSelectedListener spinnerListener = new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateFieldVisibility();
                updatePreview();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        };
        typeSpinner.setOnItemSelectedListener(spinnerListener);
        hashSpinner.setOnItemSelectedListener(spinnerListener);
        encodingSpinner.setOnItemSelectedListener(spinnerListener);

        seedText.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override
            public void onFocusChange(View v, boolean hasFocus) {
                if (!hasFocus) {
                    normalizeSeedField();
                }
            }
        });

        findViewById(R.id.otp_paste).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                pasteFromClipboard();
            }
        });
        findViewById(R.id.otp_scan).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                launchCamera();
            }
        });
        findViewById(R.id.otp_image).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                pasteImageFromClipboard();
            }
        });
        findViewById(R.id.otp_save).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                save();
            }
        });
        findViewById(R.id.otp_cancel).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });
        findViewById(R.id.otp_remove).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                remove();
            }
        });

        String initial = getIntent().getStringExtra(EXTRA_OTP_URI);
        boolean hasInitialOtp = false;
        if (initial != null && !initial.trim().isEmpty()) {
            hasInitialOtp = populateFrom(initial);
            if (!hasInitialOtp) {
                seedText.setText(initial);
            }
        } else {
            // Default to TOTP / SHA1 / BASE32 / 6 digits / 30 seconds.
            typeSpinner.setSelection(Otp.Type.TOTP.ordinal());
            hashSpinner.setSelection(Otp.Hash.SHA1.ordinal());
            encodingSpinner.setSelection(Otp.Encoding.BASE32.ordinal());
            digitsText.setText("6");
            periodText.setText("30");
            counterText.setText("0");
        }

        if (!hasInitialOtp) {
            findViewById(R.id.otp_remove).setVisibility(View.GONE);
        }

        updateFieldVisibility();
        updatePreview();
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.postDelayed(ticker, 1000);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(ticker);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacks(ticker);
        super.onDestroy();
    }

    private void setupSpinner(Spinner spinner, String[] values) {
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, values);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
    }

    private Otp.Type currentType() {
        int position = typeSpinner.getSelectedItemPosition();
        Otp.Type[] values = Otp.Type.values();
        if (position < 0 || position >= values.length) {
            return Otp.Type.TOTP;
        }
        return values[position];
    }

    private Otp.Hash currentHash() {
        int position = hashSpinner.getSelectedItemPosition();
        Otp.Hash[] values = Otp.Hash.values();
        if (position < 0 || position >= values.length) {
            return Otp.Hash.SHA1;
        }
        return values[position];
    }

    private Otp.Encoding currentEncoding() {
        int position = encodingSpinner.getSelectedItemPosition();
        Otp.Encoding[] values = Otp.Encoding.values();
        if (position < 0 || position >= values.length) {
            return Otp.Encoding.BASE32;
        }
        return values[position];
    }

    private void updateFieldVisibility() {
        Otp.Type type = currentType();
        periodText.setEnabled(type != Otp.Type.HOTP);
        counterText.setEnabled(type == Otp.Type.HOTP);
        pinText.setEnabled(type == Otp.Type.YANDEX);
        digitsText.setEnabled(type != Otp.Type.STEAM && type != Otp.Type.YANDEX);

        if (type == Otp.Type.STEAM) {
            digitsText.setText("5");
        } else if (type == Otp.Type.YANDEX) {
            digitsText.setText("8");
        }
    }

    /** Populate the form from an otpauth URI. Returns false if it could not be parsed. */
    private boolean populateFrom(String otpauth) {
        Otp otp = Otp.parse(otpauth);
        if (otp == null) {
            return false;
        }

        updating = true;
        try {
            seedText.setText(otp.getSeed());
            typeSpinner.setSelection(otp.getType().ordinal());
            hashSpinner.setSelection(otp.getHash().ordinal());
            encodingSpinner.setSelection(otp.getEncoding().ordinal());
            digitsText.setText(String.valueOf(otp.getLength()));
            periodText.setText(String.valueOf(otp.getTimeStep()));
            counterText.setText(String.valueOf(otp.getCounter()));
            pinText.setText(otp.getYandexPin());
            issuerText.setText(otp.getIssuer());
            labelText.setText(otp.getLabel());
        } finally {
            updating = false;
        }

        updateFieldVisibility();
        updatePreview();
        return true;
    }

    private void normalizeSeedField() {
        if (updating) {
            return;
        }
        String value = seedText.getText().toString().trim();
        if (value.regionMatches(true, 0, "otpauth://", 0, 10)) {
            populateFrom(value);
        }
    }

    private Otp buildOtp() {
        String seed = seedText.getText().toString().trim();
        if (seed.regionMatches(true, 0, "otpauth://", 0, 10)) {
            Otp parsed = Otp.parse(seed);
            if (parsed != null) {
                return parsed;
            }
        }

        return Otp.fromSeed(seed, currentType(), currentHash(), currentEncoding(),
                parseInt(digitsText, 6), parseInt(periodText, 30), parseInt(counterText, 0),
                issuerText.getText().toString().trim(), labelText.getText().toString().trim(),
                pinText.getText().toString().trim());
    }

    private static int parseInt(EditText view, int fallback) {
        if (view == null) {
            return fallback;
        }
        String text = view.getText().toString().trim();
        if (text.isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private void updatePreview() {
        if (updating || previewText == null) {
            return;
        }
        Otp otp = buildOtp();
        String code = null;
        if (otp != null && otp.isValid()) {
            if (otp.getType() == Otp.Type.HOTP) {
                code = otp.generate(otp.getCounter());
            } else {
                code = otp.getOtp();
            }
        }

        if (code == null || code.isEmpty()) {
            previewText.setText(R.string.otp_invalid);
        } else {
            previewText.setText(getString(R.string.otp_preview, Otp.readable(code)));
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Add from seed / clipboard / camera
    // ---------------------------------------------------------------------------------------------

    private void pasteFromClipboard() {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (clipboard == null || !clipboard.hasPrimaryClip()) {
            toast(R.string.otp_clipboard_empty);
            return;
        }
        ClipData clip = clipboard.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) {
            toast(R.string.otp_clipboard_empty);
            return;
        }
        CharSequence text = clip.getItemAt(0).coerceToText(this);
        if (text == null || text.length() == 0) {
            toast(R.string.otp_clipboard_empty);
            return;
        }
        applySeedValue(text.toString());
    }

    private void applySeedValue(String value) {
        if (value == null) {
            return;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            toast(R.string.otp_clipboard_empty);
            return;
        }
        if (trimmed.regionMatches(true, 0, "otpauth://", 0, 10) && populateFrom(trimmed)) {
            return;
        }
        if (trimmed.regionMatches(true, 0, "data:image", 0, 10)) {
            if (decodeDataUriImage(trimmed)) {
                return;
            }
        }
        seedText.setText(trimmed);
    }

    private void pasteImageFromClipboard() {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (clipboard == null || !clipboard.hasPrimaryClip()) {
            toast(R.string.otp_no_image);
            return;
        }
        ClipData clip = clipboard.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) {
            toast(R.string.otp_no_image);
            return;
        }

        for (int i = 0; i < clip.getItemCount(); i++) {
            ClipData.Item item = clip.getItemAt(i);
            Uri uri = item.getUri();
            if (uri == null && item.getIntent() != null) {
                uri = item.getIntent().getData();
            }
            if (uri != null && tryDecodeUri(uri)) {
                return;
            }
            CharSequence text = item.coerceToText(this);
            if (text != null) {
                String value = text.toString().trim();
                if (value.regionMatches(true, 0, "data:image", 0, 10)
                        && decodeDataUriImage(value)) {
                    return;
                }
            }
        }

        toast(R.string.otp_no_image);
    }

    private boolean tryDecodeUri(Uri uri) {
        Bitmap bitmap = null;
        try {
            bitmap = QrCodeDecoder.loadBitmap(getContentResolver(), uri);
            String decoded = QrCodeDecoder.decode(bitmap);
            if (decoded != null && !decoded.trim().isEmpty()) {
                applySeedValue(decoded);
                return true;
            }
        } catch (IOException e) {
            // fall through
        } catch (SecurityException e) {
            // fall through
        } catch (RuntimeException e) {
            // fall through
        } finally {
            if (bitmap != null) {
                bitmap.recycle();
            }
        }
        return false;
    }

    private boolean decodeDataUriImage(String dataUri) {
        Bitmap bitmap = null;
        try {
            int comma = dataUri.indexOf(',');
            if (comma < 0) {
                return false;
            }
            String meta = dataUri.substring(5, comma);
            String payload = dataUri.substring(comma + 1);
            byte[] bytes;
            if (meta.toLowerCase().contains("base64")) {
                bytes = Base64.decode(payload, Base64.DEFAULT);
            } else {
                bytes = URLDecoder.decode(payload, "UTF-8").getBytes("UTF-8");
            }
            bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
            String decoded = QrCodeDecoder.decode(bitmap);
            if (decoded != null && !decoded.trim().isEmpty()) {
                applySeedValue(decoded);
                return true;
            }
        } catch (Exception e) {
            // fall through
        } finally {
            if (bitmap != null) {
                bitmap.recycle();
            }
        }
        return false;
    }

    private void launchCamera() {
        try {
            File dir = new File(getCacheDir(), "otp_images");
            if (!dir.exists() && !dir.mkdirs()) {
                toast(R.string.otp_camera_error);
                return;
            }
            File file = new File(dir, "otp_" + System.currentTimeMillis() + ".jpg");
            Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".fileprovider", file);
            cameraOutputUri = uri;
            cameraOutputFile = file;

            Intent intent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
            intent.putExtra(MediaStore.EXTRA_OUTPUT, uri);
            intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    | Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(intent, REQUEST_CAMERA);
        } catch (ActivityNotFoundException e) {
            toast(R.string.otp_camera_error);
        } catch (RuntimeException e) {
            toast(R.string.otp_camera_error);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == REQUEST_CAMERA) {
            if (resultCode == RESULT_OK && cameraOutputUri != null) {
                Bitmap bitmap = null;
                try {
                    bitmap = QrCodeDecoder.loadBitmap(getContentResolver(), cameraOutputUri);
                    String decoded = QrCodeDecoder.decode(bitmap);
                    if (decoded != null && !decoded.trim().isEmpty()) {
                        applySeedValue(decoded);
                    } else {
                        toast(R.string.otp_no_qr);
                    }
                } catch (IOException e) {
                    toast(R.string.otp_no_qr);
                } catch (RuntimeException e) {
                    toast(R.string.otp_no_qr);
                } finally {
                    if (bitmap != null) {
                        bitmap.recycle();
                    }
                }
            }
            deleteCameraFile();
        }
    }

    private void deleteCameraFile() {
        if (cameraOutputFile != null) {
            //noinspection ResultOfMethodCallIgnored
            cameraOutputFile.delete();
            cameraOutputFile = null;
        }
        cameraOutputUri = null;
    }

    // ---------------------------------------------------------------------------------------------
    // Result handling
    // ---------------------------------------------------------------------------------------------

    private void save() {
        Otp otp = buildOtp();
        if (otp == null || !otp.isValid()) {
            toast(R.string.otp_invalid);
            return;
        }
        Intent result = new Intent();
        result.putExtra(EXTRA_OTP_RESULT, otp.getOtpAuthString());
        setResult(RESULT_OK, result);
        finish();
    }

    private void remove() {
        Intent result = new Intent();
        result.putExtra(EXTRA_OTP_REMOVE, true);
        setResult(RESULT_OK, result);
        finish();
    }

    private void toast(int resId) {
        Toast.makeText(this, resId, Toast.LENGTH_LONG).show();
    }
}
