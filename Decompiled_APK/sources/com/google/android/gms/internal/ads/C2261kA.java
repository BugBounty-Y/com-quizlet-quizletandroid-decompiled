package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/* renamed from: com.google.android.gms.internal.ads.kA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2261kA {
    public static final androidx.camera.core.impl.utils.executor.b d = new androidx.camera.core.impl.utils.executor.b(13);
    public final SecretKeySpec a;
    public final int b;
    public final int c;

    public C2261kA(int i, byte[] bArr) throws GeneralSecurityException {
        if (!AbstractC1981ds.j(2)) {
            throw new GeneralSecurityException("Can not use AES-CTR in FIPS-mode, as BoringCrypto module is not available.");
        }
        AbstractC1981ds.e(bArr.length);
        this.a = new SecretKeySpec(bArr, "AES");
        int blockSize = ((Cipher) d.get()).getBlockSize();
        this.c = blockSize;
        if (i > blockSize) {
            throw new GeneralSecurityException("invalid IV size");
        }
        this.b = i;
    }
}
