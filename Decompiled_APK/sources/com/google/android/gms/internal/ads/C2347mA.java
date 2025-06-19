package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* renamed from: com.google.android.gms.internal.ads.mA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2347mA implements InterfaceC2289kw {
    public final C2261kA a;
    public final C2561rA b;
    public final int c;
    public final byte[] d;

    public C2347mA(C2261kA c2261kA, C2561rA c2561rA, int i, byte[] bArr) {
        this.a = c2261kA;
        this.b = c2561rA;
        this.c = i;
        this.d = bArr;
    }

    public static C2347mA b(Aw aw) {
        byte[] bArrB = ((C2604sA) aw.d.b).b();
        Hw hw = aw.c;
        C2261kA c2261kA = new C2261kA(hw.c, bArrB);
        String strValueOf = String.valueOf(hw.f);
        As as = new As("HMAC".concat(strValueOf), new SecretKeySpec(((C2604sA) aw.e.b).b(), "HMAC"));
        int i = hw.d;
        return new C2347mA(c2261kA, new C2561rA(as, i), i, aw.f.b());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2289kw
    public final byte[] a(byte[] bArr, byte[] bArr2) throws GeneralSecurityException {
        int length = bArr.length;
        byte[] bArr3 = this.d;
        int length2 = bArr3.length;
        int i = this.c;
        if (length < i + length2) {
            throw new GeneralSecurityException("Decryption failed (ciphertext too short).");
        }
        if (!AbstractC2677ty.c(bArr3, bArr)) {
            throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
        }
        int i2 = length - i;
        byte[] bArrCopyOfRange = Arrays.copyOfRange(bArr, length2, i2);
        byte[] bArrCopyOfRange2 = Arrays.copyOfRange(bArr, i2, length);
        if (bArr2 == null) {
            bArr2 = new byte[0];
        }
        byte[] bArrR = AbstractC2457os.r(bArr2, bArrCopyOfRange, Arrays.copyOf(ByteBuffer.allocate(8).putLong(bArr2.length * 8).array(), 8));
        C2561rA c2561rA = this.b;
        byte[] bArr4 = c2561rA.d;
        int length3 = bArr4.length;
        int i3 = c2561rA.b;
        My my = c2561rA.a;
        byte[] bArr5 = c2561rA.c;
        if (!MessageDigest.isEqual(length3 > 0 ? AbstractC2457os.r(bArr5, my.a(i3, AbstractC2457os.r(bArrR, bArr4))) : AbstractC2457os.r(bArr5, my.a(i3, bArrR)), bArrCopyOfRange2)) {
            throw new GeneralSecurityException("invalid MAC");
        }
        C2261kA c2261kA = this.a;
        int length4 = bArrCopyOfRange.length;
        int i4 = c2261kA.b;
        if (length4 < i4) {
            throw new GeneralSecurityException("ciphertext too short");
        }
        byte[] bArr6 = new byte[i4];
        System.arraycopy(bArrCopyOfRange, 0, bArr6, 0, i4);
        int i5 = length4 - i4;
        byte[] bArr7 = new byte[i5];
        Cipher cipher = (Cipher) C2261kA.d.get();
        byte[] bArr8 = new byte[c2261kA.c];
        System.arraycopy(bArr6, 0, bArr8, 0, i4);
        cipher.init(2, c2261kA.a, new IvParameterSpec(bArr8));
        if (cipher.doFinal(bArrCopyOfRange, i4, i5, bArr7, 0) == i5) {
            return bArr7;
        }
        throw new GeneralSecurityException("stored output's length does not match input's length");
    }
}
