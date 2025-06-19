package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class L0 extends AbstractC1816a0 {
    public final /* synthetic */ InterfaceC2122h0 b;
    public final /* synthetic */ androidx.compose.foundation.gestures.l1 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L0(androidx.compose.foundation.gestures.l1 l1Var, InterfaceC2122h0 interfaceC2122h0, InterfaceC2122h0 interfaceC2122h02) {
        super(interfaceC2122h0);
        this.b = interfaceC2122h02;
        this.c = l1Var;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1816a0, com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        C2078g0 c2078g0B = this.b.b(j);
        C2166i0 c2166i0 = c2078g0B.a;
        long j2 = c2166i0.b;
        long j3 = this.c.b;
        C2166i0 c2166i02 = new C2166i0(c2166i0.a, j2 + j3);
        C2166i0 c2166i03 = c2078g0B.b;
        return new C2078g0(c2166i02, new C2166i0(c2166i03.a, c2166i03.b + j3));
    }
}
