package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.hx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2162hx extends AbstractC2761vw {
    public final C2247jx c;
    public final C2883yp d;
    public final C2604sA e;
    public final Integer f;

    public C2162hx(C2247jx c2247jx, C2883yp c2883yp, C2604sA c2604sA, Integer num) {
        super(9);
        this.c = c2247jx;
        this.d = c2883yp;
        this.e = c2604sA;
        this.f = num;
    }

    public static C2162hx S(Lw lw, C2883yp c2883yp, Integer num) throws GeneralSecurityException {
        C2604sA c2604sAB;
        Lw lw2 = Lw.j;
        String str = lw.b;
        if (lw != lw2 && num == null) {
            throw new GeneralSecurityException(android.support.v4.media.session.a.B("For given Variant ", str, " the value of idRequirement must be non-null"));
        }
        if (lw == lw2 && num != null) {
            throw new GeneralSecurityException("For given Variant NO_PREFIX the value of idRequirement must be null");
        }
        C2604sA c2604sA = (C2604sA) c2883yp.b;
        if (c2604sA.a.length != 32) {
            throw new GeneralSecurityException(android.support.v4.media.session.a.f(c2604sA.a.length, "XChaCha20Poly1305 key must be constructed with key of length 32 bytes, not "));
        }
        C2247jx c2247jx = new C2247jx(lw);
        if (lw == lw2) {
            c2604sAB = Yx.a;
        } else if (lw == Lw.i) {
            c2604sAB = Yx.a(num.intValue());
        } else {
            if (lw != Lw.h) {
                throw new IllegalStateException("Unknown Variant: ".concat(str));
            }
            c2604sAB = Yx.b(num.intValue());
        }
        return new C2162hx(c2247jx, c2883yp, c2604sAB, num);
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
