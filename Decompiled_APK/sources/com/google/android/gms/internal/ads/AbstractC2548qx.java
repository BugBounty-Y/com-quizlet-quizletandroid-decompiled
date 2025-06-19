package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.qx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2548qx {
    public static final C1944cy a;
    public static final Zx b;
    public static final Ix c;
    public static final Gx d;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.AesGcmSivKey");
        a = new C1944cy(Sw.class, new C2290kx(12));
        b = new Zx(c2604sAB, new C2290kx(13));
        c = new Ix(Qw.class, new C2290kx(14));
        d = new Gx(c2604sAB, new C2290kx(15));
    }

    public static Ew a(Yz yz) throws GeneralSecurityException {
        int iOrdinal = yz.ordinal();
        if (iOrdinal == 1) {
            return Ew.h;
        }
        if (iOrdinal != 2) {
            if (iOrdinal == 3) {
                return Ew.j;
            }
            if (iOrdinal != 4) {
                throw new GeneralSecurityException(android.support.v4.media.session.a.f(yz.a(), "Unable to parse OutputPrefixType: "));
            }
        }
        return Ew.i;
    }

    public static Yz b(Ew ew) throws GeneralSecurityException {
        if (Ew.h.equals(ew)) {
            return Yz.TINK;
        }
        if (Ew.i.equals(ew)) {
            return Yz.CRUNCHY;
        }
        if (Ew.j.equals(ew)) {
            return Yz.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: ".concat(String.valueOf(ew)));
    }
}
