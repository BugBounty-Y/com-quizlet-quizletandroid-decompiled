package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* loaded from: classes2.dex */
public final class Tw extends AbstractC2761vw {
    public final Vw c;
    public final C2883yp d;
    public final C2604sA e;
    public final Integer f;

    public Tw(Vw vw, C2883yp c2883yp, C2604sA c2604sA, Integer num) {
        super(9);
        this.c = vw;
        this.d = c2883yp;
        this.e = c2604sA;
        this.f = num;
    }

    public static Tw S(Gw gw, C2883yp c2883yp, Integer num) throws GeneralSecurityException {
        C2604sA c2604sAB;
        Gw gw2 = Gw.h;
        String str = gw.b;
        if (gw != gw2 && num == null) {
            throw new GeneralSecurityException(android.support.v4.media.session.a.B("For given Variant ", str, " the value of idRequirement must be non-null"));
        }
        if (gw == gw2 && num != null) {
            throw new GeneralSecurityException("For given Variant NO_PREFIX the value of idRequirement must be null");
        }
        C2604sA c2604sA = (C2604sA) c2883yp.b;
        if (c2604sA.a.length != 32) {
            throw new GeneralSecurityException(android.support.v4.media.session.a.f(c2604sA.a.length, "ChaCha20Poly1305 key must be constructed with key of length 32 bytes, not "));
        }
        Vw vw = new Vw(gw);
        if (gw == gw2) {
            c2604sAB = Yx.a;
        } else if (gw == Gw.g) {
            c2604sAB = Yx.a(num.intValue());
        } else {
            if (gw != Gw.f) {
                throw new IllegalStateException("Unknown Variant: ".concat(str));
            }
            c2604sAB = Yx.b(num.intValue());
        }
        return new Tw(vw, c2883yp, c2604sAB, num);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2761vw
    public final C2604sA R() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2025es
    public final /* synthetic */ AbstractC2547qw g() {
        return this.c;
    }
}
