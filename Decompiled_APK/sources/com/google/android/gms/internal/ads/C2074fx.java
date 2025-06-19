package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.fx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2074fx extends AbstractC2761vw {
    public final C2118gx c;
    public final C2883yp d;
    public final C2604sA e;
    public final Integer f;

    public C2074fx(C2118gx c2118gx, C2883yp c2883yp, C2604sA c2604sA, Integer num) {
        super(9);
        this.c = c2118gx;
        this.d = c2883yp;
        this.e = c2604sA;
        this.f = num;
    }

    public static C2074fx S(C2118gx c2118gx, C2883yp c2883yp, Integer num) throws GeneralSecurityException {
        C2604sA c2604sAB;
        Gw gw = c2118gx.a;
        Gw gw2 = Gw.j;
        String str = gw.b;
        if (gw != gw2 && num == null) {
            throw new GeneralSecurityException(android.support.v4.media.session.a.B("For given Variant ", str, " the value of idRequirement must be non-null"));
        }
        if (gw == gw2 && num != null) {
            throw new GeneralSecurityException("For given Variant NO_PREFIX the value of idRequirement must be null");
        }
        C2604sA c2604sA = (C2604sA) c2883yp.b;
        if (c2604sA.a.length != 32) {
            throw new GeneralSecurityException(android.support.v4.media.session.a.f(c2604sA.a.length, "XAesGcmKey key must be constructed with key of length 32 bytes, not "));
        }
        if (gw == gw2) {
            c2604sAB = Yx.a;
        } else {
            if (gw != Gw.i) {
                throw new IllegalStateException("Unknown Variant: ".concat(str));
            }
            c2604sAB = Yx.b(num.intValue());
        }
        return new C2074fx(c2118gx, c2883yp, c2604sAB, num);
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
