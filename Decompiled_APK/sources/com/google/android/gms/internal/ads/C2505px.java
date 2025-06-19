package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* renamed from: com.google.android.gms.internal.ads.px, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2505px implements InterfaceC2289kw {
    public static final byte[] c = AbstractC2543qs.k("7a806c");
    public static final byte[] d = AbstractC2543qs.k("46bb91c3c5");
    public static final byte[] e = AbstractC2543qs.k("36864200e0eaf5284d884a0e77d31646");
    public static final byte[] f = AbstractC2543qs.k("bae8e37fc83441b16034566b");
    public static final byte[] g = AbstractC2543qs.k("af60eb711bd85bc1e4d3e0a462e074eea428a8");
    public final SecretKeySpec a;
    public final byte[] b;

    public C2505px(byte[] bArr, byte[] bArr2) throws InvalidAlgorithmParameterException {
        this.b = bArr2;
        AbstractC1981ds.e(bArr.length);
        this.a = new SecretKeySpec(bArr, "AES");
    }

    public static boolean b(Cipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            byte[] bArr = f;
            cipher.init(2, new SecretKeySpec(e, "AES"), new GCMParameterSpec(128, bArr, 0, bArr.length));
            cipher.updateAAD(d);
            byte[] bArr2 = g;
            return MessageDigest.isEqual(cipher.doFinal(bArr2, 0, bArr2.length), c);
        } catch (GeneralSecurityException unused) {
            return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2289kw
    public final byte[] a(byte[] bArr, byte[] bArr2) throws GeneralSecurityException {
        int length = bArr.length;
        byte[] bArr3 = this.b;
        int length2 = bArr3.length;
        if (length < length2 + 28) {
            throw new GeneralSecurityException("ciphertext too short");
        }
        if (!AbstractC2677ty.c(bArr3, bArr)) {
            throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
        }
        Cipher cipherC = Bx.c();
        cipherC.init(2, this.a, new GCMParameterSpec(128, bArr, length2, 12));
        if (bArr2 != null && bArr2.length != 0) {
            cipherC.updateAAD(bArr2);
        }
        return cipherC.doFinal(bArr, length2 + 12, (length - length2) - 12);
    }
}
