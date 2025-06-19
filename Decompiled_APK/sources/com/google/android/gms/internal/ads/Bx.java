package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;

/* loaded from: classes2.dex */
public abstract class Bx implements InterfaceC2289kw {
    public static final androidx.camera.core.impl.utils.executor.b a = new androidx.camera.core.impl.utils.executor.b(11);

    public static C2505px b(Qw qw) {
        byte[] bArr = C2505px.c;
        if (C2505px.b(c())) {
            return new C2505px(((C2604sA) qw.d.b).b(), qw.e.b());
        }
        throw new IllegalStateException("Cipher does not implement AES GCM SIV.");
    }

    public static /* synthetic */ Cipher c() throws GeneralSecurityException {
        try {
            Cipher cipher = (Cipher) a.get();
            if (cipher != null) {
                return cipher;
            }
            throw new GeneralSecurityException("AES GCM SIV cipher is invalid.");
        } catch (IllegalStateException e) {
            throw new GeneralSecurityException("AES GCM SIV cipher is not available or is invalid.", e);
        }
    }
}
