package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Tg implements CC {
    public final /* synthetic */ int a;
    public final Sg b;

    public /* synthetic */ Tg(Sg sg, int i) {
        this.a = i;
        this.b = sg;
    }

    public C2023eq a() {
        C2023eq c2023eq = this.b.b;
        AbstractC1981ds.s(c2023eq);
        return c2023eq;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return this.b.c;
            case 1:
                return this.b.e;
            case 2:
                return Integer.valueOf(this.b.g);
            case 3:
                return this.b.d;
            case 4:
                C2023eq c2023eq = this.b.b;
                AbstractC1981ds.s(c2023eq);
                return c2023eq;
            default:
                return this.b.a();
        }
    }
}
