package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.zx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2934zx {
    public static final C1944cy a;
    public static final Zx b;
    public static final Ix c;
    public static final Gx d;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.XAesGcmKey");
        a = new C1944cy(C2118gx.class, new C2290kx(20));
        b = new Zx(c2604sAB, new C2290kx(21));
        c = new Ix(C2074fx.class, new C2290kx(22));
        d = new Gx(c2604sAB, new C2290kx(23));
    }

    public static Gw a(Yz yz) throws GeneralSecurityException {
        int iOrdinal = yz.ordinal();
        if (iOrdinal == 1) {
            return Gw.i;
        }
        if (iOrdinal == 3) {
            return Gw.j;
        }
        throw new GeneralSecurityException(android.support.v4.media.session.a.f(yz.a(), "Unable to parse OutputPrefixType: "));
    }

    public static Yz b(Gw gw) throws GeneralSecurityException {
        if (gw.equals(Gw.i)) {
            return Yz.TINK;
        }
        if (gw.equals(Gw.j)) {
            return Yz.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: ".concat(gw.b));
    }
}
