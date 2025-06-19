package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Vt extends Xt {
    public final /* synthetic */ int f;
    public final /* synthetic */ Zt g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Vt(Zt zt, int i) {
        super(zt);
        this.f = i;
        this.g = zt;
    }

    @Override // com.google.android.gms.internal.ads.Xt
    public final Object a(int i) {
        Zt zt = this.g;
        switch (this.f) {
            case 0:
                Object obj = Zt.j;
                return zt.b()[i];
            case 1:
                return new Yt(zt, i);
            default:
                Object obj2 = Zt.j;
                return zt.d()[i];
        }
    }
}
