package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Sj implements CC {
    public final /* synthetic */ int a;
    public final C2702ug b;
    public final C2153ho c;
    public final C1969df d;

    public /* synthetic */ Sj(C2702ug c2702ug, C2153ho c2153ho, C1969df c1969df, int i) {
        this.a = i;
        this.b = c2702ug;
        this.c = c2153ho;
        this.d = c1969df;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new Rj((String) this.b.b.d, (Ui) this.c.zzb(), this.d.a());
            default:
                return new Tj((String) this.b.b.d, (Ui) this.c.zzb(), this.d.a());
        }
    }
}
