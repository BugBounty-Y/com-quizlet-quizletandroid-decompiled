package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.sx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2633sx {
    public static final C1944cy a;
    public static final Zx b;
    public static final Ix c;
    public static final Gx d;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key");
        a = new C1944cy(Vw.class, new C2290kx(16));
        b = new Zx(c2604sAB, new C2290kx(17));
        c = new Ix(Tw.class, new C2290kx(18));
        d = new Gx(c2604sAB, new C2290kx(19));
    }

    public static Gw a(Yz yz) throws GeneralSecurityException {
        int iOrdinal = yz.ordinal();
        if (iOrdinal == 1) {
            return Gw.f;
        }
        if (iOrdinal != 2) {
            if (iOrdinal == 3) {
                return Gw.h;
            }
            if (iOrdinal != 4) {
                throw new GeneralSecurityException(android.support.v4.media.session.a.f(yz.a(), "Unable to parse OutputPrefixType: "));
            }
        }
        return Gw.g;
    }

    public static Yz b(Gw gw) throws GeneralSecurityException {
        if (Gw.f.equals(gw)) {
            return Yz.TINK;
        }
        if (Gw.g.equals(gw)) {
            return Yz.CRUNCHY;
        }
        if (Gw.h.equals(gw)) {
            return Yz.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: ".concat(gw.b));
    }
}
