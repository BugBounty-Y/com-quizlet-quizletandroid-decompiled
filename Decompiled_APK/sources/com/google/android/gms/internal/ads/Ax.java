package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* loaded from: classes2.dex */
public abstract class Ax {
    public static final C1944cy a;
    public static final Zx b;
    public static final Ix c;
    public static final Gx d;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");
        a = new C1944cy(C2247jx.class, new C2290kx(24));
        b = new Zx(c2604sAB, new C2290kx(25));
        c = new Ix(C2162hx.class, new C2290kx(26));
        d = new Gx(c2604sAB, new C2290kx(27));
    }

    public static Lw a(Yz yz) throws GeneralSecurityException {
        int iOrdinal = yz.ordinal();
        if (iOrdinal == 1) {
            return Lw.h;
        }
        if (iOrdinal != 2) {
            if (iOrdinal == 3) {
                return Lw.j;
            }
            if (iOrdinal != 4) {
                throw new GeneralSecurityException(android.support.v4.media.session.a.f(yz.a(), "Unable to parse OutputPrefixType: "));
            }
        }
        return Lw.i;
    }

    public static Yz b(Lw lw) throws GeneralSecurityException {
        if (Lw.h.equals(lw)) {
            return Yz.TINK;
        }
        if (Lw.i.equals(lw)) {
            return Yz.CRUNCHY;
        }
        if (Lw.j.equals(lw)) {
            return Yz.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: ".concat(lw.b));
    }
}
