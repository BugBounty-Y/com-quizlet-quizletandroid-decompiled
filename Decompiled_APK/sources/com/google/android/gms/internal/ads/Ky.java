package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* loaded from: classes2.dex */
public abstract class Ky {
    public static final C1944cy a;
    public static final Zx b;
    public static final Ix c;
    public static final Gx d;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.AesCmacKey");
        a = new C1944cy(C2892yy.class, new C2806wy(5));
        b = new Zx(c2604sAB, new C2806wy(6));
        c = new Ix(C2720uy.class, new C2806wy(7));
        d = new Gx(c2604sAB, new C2806wy(8));
    }

    public static C2332lw a(Yz yz) throws GeneralSecurityException {
        int iOrdinal = yz.ordinal();
        if (iOrdinal == 1) {
            return C2332lw.o;
        }
        if (iOrdinal == 2) {
            return C2332lw.q;
        }
        if (iOrdinal == 3) {
            return C2332lw.r;
        }
        if (iOrdinal == 4) {
            return C2332lw.p;
        }
        throw new GeneralSecurityException(android.support.v4.media.session.a.f(yz.a(), "Unable to parse OutputPrefixType: "));
    }

    public static Yz b(C2332lw c2332lw) throws GeneralSecurityException {
        if (C2332lw.o.equals(c2332lw)) {
            return Yz.TINK;
        }
        if (C2332lw.p.equals(c2332lw)) {
            return Yz.CRUNCHY;
        }
        if (C2332lw.r.equals(c2332lw)) {
            return Yz.RAW;
        }
        if (C2332lw.q.equals(c2332lw)) {
            return Yz.LEGACY;
        }
        throw new GeneralSecurityException("Unable to serialize variant: ".concat(String.valueOf(c2332lw)));
    }
}
