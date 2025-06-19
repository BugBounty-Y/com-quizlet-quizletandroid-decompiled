package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.ox, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2462ox {
    public static final C1944cy a;
    public static final Zx b;
    public static final Ix c;
    public static final Gx d;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.AesGcmKey");
        a = new C1944cy(Pw.class, new C2290kx(8));
        b = new Zx(c2604sAB, new C2290kx(9));
        c = new Ix(Nw.class, new C2290kx(10));
        d = new Gx(c2604sAB, new C2290kx(11));
    }

    public static C2332lw a(Yz yz) throws GeneralSecurityException {
        int iOrdinal = yz.ordinal();
        if (iOrdinal == 1) {
            return C2332lw.f;
        }
        if (iOrdinal != 2) {
            if (iOrdinal == 3) {
                return C2332lw.h;
            }
            if (iOrdinal != 4) {
                throw new GeneralSecurityException(android.support.v4.media.session.a.f(yz.a(), "Unable to parse OutputPrefixType: "));
            }
        }
        return C2332lw.g;
    }

    public static Yz b(C2332lw c2332lw) throws GeneralSecurityException {
        if (C2332lw.f.equals(c2332lw)) {
            return Yz.TINK;
        }
        if (C2332lw.g.equals(c2332lw)) {
            return Yz.CRUNCHY;
        }
        if (C2332lw.h.equals(c2332lw)) {
            return Yz.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: ".concat(String.valueOf(c2332lw)));
    }
}
