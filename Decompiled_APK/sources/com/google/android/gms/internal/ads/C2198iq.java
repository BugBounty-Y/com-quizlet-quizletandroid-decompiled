package com.google.android.gms.internal.ads;

import android.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.iq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2198iq {
    public static final String a(byte[] bArr, byte[] bArr2, String str, Ek ek) throws GeneralSecurityException {
        C2326lq c2326lqC;
        if (str != null) {
            try {
                try {
                    c2326lqC = AbstractC1981ds.c(new Lr(new ByteArrayInputStream(Base64.decode(str, 11)), 3));
                } catch (IOException unused) {
                    throw new GeneralSecurityException("Parse keyset failed");
                }
            } catch (GeneralSecurityException e) {
                com.google.android.gms.ads.internal.util.A.l("Failed to get keysethandle".concat(e.toString()));
                com.google.android.gms.ads.internal.j.C.h.h("CryptoUtils.getHandle", e);
                c2326lqC = null;
            }
            if (c2326lqC != null) {
                try {
                    byte[] bArrA = ((InterfaceC2289kw) c2326lqC.B(AbstractC2718uw.a())).a(bArr, bArr2);
                    ek.a.put("ds", "1");
                    return new String(bArrA, "UTF-8");
                } catch (UnsupportedEncodingException | UnsupportedOperationException | GeneralSecurityException e2) {
                    com.google.android.gms.ads.internal.util.A.l("Failed to decrypt ".concat(e2.toString()));
                    com.google.android.gms.ads.internal.j.C.h.h("CryptoUtils.decrypt", e2);
                    ek.a.put("dsf", e2.toString());
                }
            }
        }
        return null;
    }
}
