package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* renamed from: com.google.android.gms.internal.ads.wx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2805wx implements InterfaceC2289kw {
    public final /* synthetic */ int a;
    public final byte[] b;
    public final Object c;

    public C2805wx(int i, byte[] bArr, byte[] bArr2) throws GeneralSecurityException {
        this.a = i;
        switch (i) {
            case 3:
                this.c = new C2762vx(0, bArr);
                this.b = bArr2;
                return;
            case 4:
                this.c = new C2762vx(1, bArr);
                this.b = bArr2;
                return;
            default:
                if (!AbstractC1981ds.j(1)) {
                    throw new GeneralSecurityException("Can not use ChaCha20Poly1305 in FIPS-mode.");
                }
                if (((Cipher) C2590rx.f.get()) == null) {
                    throw new GeneralSecurityException("JCE does not support algorithm: ChaCha20-Poly1305");
                }
                if (bArr.length != 32) {
                    throw new InvalidKeyException("The key length in bytes must be 32.");
                }
                this.b = bArr;
                this.c = bArr2;
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2289kw
    public final byte[] a(byte[] bArr, byte[] bArr2) throws GeneralSecurityException {
        Object obj = this.c;
        byte[] bArr3 = this.b;
        switch (this.a) {
            case 0:
                InterfaceC2289kw interfaceC2289kw = (InterfaceC2289kw) obj;
                if (bArr3.length == 0) {
                    return interfaceC2289kw.a(bArr, bArr2);
                }
                if (AbstractC2677ty.c(bArr3, bArr)) {
                    return interfaceC2289kw.a(Arrays.copyOfRange(bArr, 5, bArr.length), bArr2);
                }
                throw new GeneralSecurityException("wrong prefix");
            case 1:
                if (bArr == null) {
                    throw new NullPointerException("ciphertext is null");
                }
                int length = bArr.length;
                byte[] bArr4 = (byte[]) obj;
                int length2 = bArr4.length;
                if (length < length2 + 40) {
                    throw new GeneralSecurityException("ciphertext too short");
                }
                if (!AbstractC2677ty.c(bArr4, bArr)) {
                    throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
                }
                byte[] bArr5 = new byte[24];
                System.arraycopy(bArr, length2, bArr5, 0, 24);
                int[] iArrC = AbstractC2676tx.c(AbstractC2676tx.d(bArr3), AbstractC2676tx.d(bArr5));
                ByteBuffer byteBufferOrder = ByteBuffer.allocate(iArrC.length * 4).order(ByteOrder.LITTLE_ENDIAN);
                byteBufferOrder.asIntBuffer().put(iArrC);
                SecretKeySpec secretKeySpec = new SecretKeySpec(byteBufferOrder.array(), "ChaCha20");
                byte[] bArr6 = new byte[12];
                System.arraycopy(bArr5, 16, bArr6, 4, 8);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(bArr6);
                Cipher cipher = (Cipher) C2590rx.f.get();
                cipher.init(2, secretKeySpec, ivParameterSpec);
                if (bArr2 != null && bArr2.length != 0) {
                    cipher.updateAAD(bArr2);
                }
                return cipher.doFinal(bArr, 24 + length2, (length - length2) - 24);
            case 2:
                if (bArr == null) {
                    throw new NullPointerException("ciphertext is null");
                }
                int length3 = bArr.length;
                int length4 = bArr3.length;
                if (length3 < length4 + 28) {
                    throw new GeneralSecurityException("ciphertext too short");
                }
                if (!AbstractC2677ty.c(bArr3, bArr)) {
                    throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
                }
                androidx.camera.core.impl.utils.executor.b bVar = AbstractC2419nx.a;
                Objects.equals(System.getProperty("java.vendor"), "The Android Project");
                GCMParameterSpec gCMParameterSpec = new GCMParameterSpec(128, bArr, length4, 12);
                Cipher cipher2 = (Cipher) AbstractC2419nx.a.get();
                cipher2.init(2, (SecretKeySpec) obj, gCMParameterSpec);
                if (bArr2 != null && bArr2.length != 0) {
                    cipher2.updateAAD(bArr2);
                }
                return cipher2.doFinal(bArr, 12 + length4, (length3 - length4) - 12);
            case 3:
                int length5 = bArr3.length;
                if (length5 == 0) {
                    return b(bArr, bArr2);
                }
                if (AbstractC2677ty.c(bArr3, bArr)) {
                    return b(Arrays.copyOfRange(bArr, length5, bArr.length), bArr2);
                }
                throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
            default:
                int length6 = bArr3.length;
                if (length6 == 0) {
                    return c(bArr, bArr2);
                }
                if (AbstractC2677ty.c(bArr3, bArr)) {
                    return c(Arrays.copyOfRange(bArr, length6, bArr.length), bArr2);
                }
                throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
        }
    }

    public byte[] b(byte[] bArr, byte[] bArr2) throws GeneralSecurityException {
        int length = bArr.length;
        if (length < 28) {
            throw new GeneralSecurityException("ciphertext too short");
        }
        return ((C2762vx) this.c).r(ByteBuffer.wrap(bArr, 12, length - 12), Arrays.copyOf(bArr, 12), bArr2);
    }

    public byte[] c(byte[] bArr, byte[] bArr2) throws GeneralSecurityException {
        int length = bArr.length;
        if (length < 40) {
            throw new GeneralSecurityException("ciphertext too short");
        }
        return ((C2762vx) this.c).r(ByteBuffer.wrap(bArr, 24, length - 24), Arrays.copyOf(bArr, 24), bArr2);
    }

    public C2805wx(InterfaceC2289kw interfaceC2289kw, byte[] bArr) {
        this.a = 0;
        this.c = interfaceC2289kw;
        int length = bArr.length;
        if (length != 0 && length != 5) {
            throw new IllegalArgumentException("identifier has an invalid length");
        }
        this.b = bArr;
    }

    public C2805wx(byte[] bArr, C2604sA c2604sA) throws GeneralSecurityException {
        this.a = 2;
        if (AbstractC1981ds.j(2)) {
            androidx.camera.core.impl.utils.executor.b bVar = AbstractC2419nx.a;
            AbstractC1981ds.e(bArr.length);
            this.c = new SecretKeySpec(bArr, "AES");
            this.b = c2604sA.b();
            return;
        }
        throw new GeneralSecurityException("Can not use AES-GCM in FIPS-mode, as BoringCrypto module is not available.");
    }
}
