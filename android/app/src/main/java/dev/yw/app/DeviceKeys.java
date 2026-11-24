package dev.yw.app;

import android.app.ActivityManager;
import android.app.KeyguardManager;
import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import java.security.Key;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * The platform services behind the I/O requests (spec/15 §5.2-§5.3, §3.2; 2026-11-25 A2-4b): the Keystore device
 * key yw.device.v1 that wraps each file's 32-byte key, and the memory facts before an Argon2 run.
 *
 * <p>The device key: AES-256-GCM in AndroidKeyStore, no user authentication, not exportable, no StrongBox (§5.2),
 * setUnlockedDeviceRequired(true) (§5.2, N25), setRandomizedEncryptionRequired(true): the Keystore makes every
 * encryption IV and neither Java nor Rust ever supplies one (P0-10); unwrapping gives the IV read from the envelope.
 * AAD = the kind's string. A wrap makes the key when it does not exist yet; an unwrap never does (a missing key is
 * KEY_MISSING: the files cannot be opened, fail closed, and no new key replaces the lost one silently). A key that
 * cannot be made means no wallet (§5.2).
 *
 * <p>Errors are fixed statuses ({@link IoFrame}); no exception's class or message goes anywhere (§3.3). The plain
 * file key: the wrap reads it straight from the request frame (which the I/O thread zeroes after), and the unwrap's
 * result array is zeroed by the I/O thread right after ioComplete (§3.2). Copies inside Cipher, binder and the
 * keystore daemon are the residual of §5.2.
 */
final class DeviceKeys {
    /** The Keystore alias of the device key. */
    static final String ALIAS = "yw.device.v1";

    private static final String STORE = "AndroidKeyStore";
    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int TAG_BITS = 128;

    private DeviceKeys() {}

    /** A status and, for OK, the answer body. */
    static final class Answer {
        final int status;
        final byte[] body;

        private Answer(int status, byte[] body) {
            this.status = status;
            this.body = body;
        }

        static Answer of(int status) {
            return new Answer(status, null);
        }

        static Answer ok(byte[] body) {
            return new Answer(IoFrame.OK, body);
        }
    }

    private static SecretKey load() throws Exception {
        KeyStore store = KeyStore.getInstance(STORE);
        store.load(null);
        Key key = store.getKey(ALIAS, null);
        return key instanceof SecretKey ? (SecretKey) key : null;
    }

    private static SecretKey create() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE);
        generator.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .setUnlockedDeviceRequired(true)
                .build());
        return generator.generateKey();
    }

    private static int failure(Context context, Throwable error) {
        if (error instanceof AEADBadTagException) {
            return IoFrame.CRYPTO_FAILED;
        }
        if (error instanceof KeyPermanentlyInvalidatedException) {
            return IoFrame.KEY_FAILED;
        }
        KeyguardManager keyguard = context.getSystemService(KeyguardManager.class);
        if (keyguard != null && keyguard.isDeviceLocked()) {
            return IoFrame.DEVICE_LOCKED;
        }
        return IoFrame.OTHER;
    }

    /** Wraps the file key in frame's body for frame's kind: GCM iv ‖ ct ‖ tag (60 bytes). */
    static Answer wrap(Context context, byte[] frame) {
        byte[] aad = IoFrame.aad(IoFrame.kind(frame));
        if (aad == null || frame.length != IoFrame.HEADER + IoFrame.KEY_LEN) {
            return Answer.of(IoFrame.BAD_REQUEST);
        }
        SecretKey key;
        try {
            key = load();
            if (key == null) {
                key = create();
            }
        } catch (Throwable error) {
            return Answer.of(IoFrame.KEY_FAILED);
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipher.updateAAD(aad);
            byte[] sealed = cipher.doFinal(frame, IoFrame.HEADER, IoFrame.KEY_LEN);
            byte[] iv = cipher.getIV();
            if (iv == null || iv.length != IoFrame.IV_LEN || sealed.length != IoFrame.WRAPPED_LEN - IoFrame.IV_LEN) {
                return Answer.of(IoFrame.OTHER);
            }
            byte[] out = Arrays.copyOf(iv, IoFrame.WRAPPED_LEN);
            System.arraycopy(sealed, 0, out, IoFrame.IV_LEN, sealed.length);
            return Answer.ok(out);
        } catch (Throwable error) {
            return Answer.of(failure(context, error));
        }
    }

    /** Unwraps frame's body (GCM iv ‖ ct ‖ tag) for frame's kind: the 32-byte file key. */
    static Answer unwrap(Context context, byte[] frame) {
        byte[] aad = IoFrame.aad(IoFrame.kind(frame));
        if (aad == null || frame.length != IoFrame.HEADER + IoFrame.WRAPPED_LEN) {
            return Answer.of(IoFrame.BAD_REQUEST);
        }
        SecretKey key;
        try {
            key = load();
        } catch (Throwable error) {
            return Answer.of(IoFrame.KEY_FAILED);
        }
        if (key == null) {
            return Answer.of(IoFrame.KEY_MISSING);
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, frame, IoFrame.HEADER, IoFrame.IV_LEN));
            cipher.updateAAD(aad);
            byte[] plain = cipher.doFinal(frame, IoFrame.HEADER + IoFrame.IV_LEN, IoFrame.WRAPPED_LEN - IoFrame.IV_LEN);
            if (plain.length != IoFrame.KEY_LEN) {
                Arrays.fill(plain, (byte) 0);
                return Answer.of(IoFrame.CRYPTO_FAILED);
            }
            return Answer.ok(plain);
        } catch (Throwable error) {
            return Answer.of(failure(context, error));
        }
    }

    /** The memory facts now (§5.3): ActivityManager.MemoryInfo and isLowRamDevice(). */
    static Answer memory(Context context) {
        ActivityManager manager = context.getSystemService(ActivityManager.class);
        if (manager == null) {
            return Answer.of(IoFrame.OTHER);
        }
        ActivityManager.MemoryInfo info = new ActivityManager.MemoryInfo();
        manager.getMemoryInfo(info);
        return Answer.ok(IoFrame.memoryFacts(
                info.totalMem, info.availMem, info.threshold, info.lowMemory, manager.isLowRamDevice()));
    }
}
