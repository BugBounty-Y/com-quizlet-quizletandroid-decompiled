package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.ax, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1856ax {
    public static final C1944cy a;
    public static final Zx b;
    public static final Ix c;
    public static final Gx d;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.KmsAeadKey");
        a = new C1944cy(Zw.class, new Is(20));
        b = new Zx(c2604sAB, new Is(21));
        c = new Ix(Yw.class, new Is(22));
        d = new Gx(c2604sAB, new Is(23));
    }

    public static Lw a(Yz yz) throws GeneralSecurityException {
        int iOrdinal = yz.ordinal();
        if (iOrdinal == 1) {
            return Lw.f;
        }
        if (iOrdinal == 3) {
            return Lw.g;
        }
        throw new GeneralSecurityException(android.support.v4.media.session.a.f(yz.a(), "Unable to parse OutputPrefixType: "));
    }

    public static Yz b(Lw lw) throws GeneralSecurityException {
        if (Lw.f.equals(lw)) {
            return Yz.TINK;
        }
        if (Lw.g.equals(lw)) {
            return Yz.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: ".concat(lw.b));
    }
}
