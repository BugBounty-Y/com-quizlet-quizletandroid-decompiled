package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.bx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1900bx extends AbstractC2761vw {
    public final C1943cx c;
    public final C2604sA d;
    public final Integer e;

    public C1900bx(C1943cx c1943cx, C2604sA c2604sA, Integer num) {
        super(9);
        this.c = c1943cx;
        this.d = c2604sA;
        this.e = num;
    }

    public static C1900bx S(C1943cx c1943cx, Integer num) throws GeneralSecurityException {
        C2604sA c2604sAB;
        Ew ew = c1943cx.a;
        if (ew == Ew.l) {
            if (num != null) {
                throw new GeneralSecurityException("For given Variant NO_PREFIX the value of idRequirement must be null");
            }
            c2604sAB = Yx.a;
        } else {
            if (ew != Ew.k) {
                throw new GeneralSecurityException("Unknown Variant: ".concat(String.valueOf(ew)));
            }
            if (num == null) {
                throw new GeneralSecurityException("For given Variant TINK the value of idRequirement must be non-null");
            }
            c2604sAB = Yx.b(num.intValue());
        }
        return new C1900bx(c1943cx, c2604sAB, num);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2761vw
    public final C2604sA R() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2025es
    public final /* synthetic */ AbstractC2547qw g() {
        return this.c;
    }
}
