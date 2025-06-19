package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.mx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2376mx {
    public static final C1944cy a;
    public static final Zx b;
    public static final Ix c;
    public static final Gx d;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.AesEaxKey");
        a = new C1944cy(Mw.class, new C2290kx(4));
        b = new Zx(c2604sAB, new C2290kx(5));
        c = new Ix(Jw.class, new C2290kx(6));
        d = new Gx(c2604sAB, new C2290kx(7));
    }

    public static Lw a(Yz yz) throws GeneralSecurityException {
        int iOrdinal = yz.ordinal();
        if (iOrdinal == 1) {
            return Lw.c;
        }
        if (iOrdinal != 2) {
            if (iOrdinal == 3) {
                return Lw.e;
            }
            if (iOrdinal != 4) {
                throw new GeneralSecurityException(android.support.v4.media.session.a.f(yz.a(), "Unable to parse OutputPrefixType: "));
            }
        }
        return Lw.d;
    }

    public static Yz b(Lw lw) throws GeneralSecurityException {
        if (Lw.c.equals(lw)) {
            return Yz.TINK;
        }
        if (Lw.d.equals(lw)) {
            return Yz.CRUNCHY;
        }
        if (Lw.e.equals(lw)) {
            return Yz.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: ".concat(String.valueOf(lw)));
    }
}
