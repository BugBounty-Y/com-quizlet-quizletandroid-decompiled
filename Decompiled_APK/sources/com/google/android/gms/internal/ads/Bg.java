package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Bg implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final Tg c;

    public /* synthetic */ Bg(BC bc, Tg tg, int i) {
        this.a = i;
        this.b = bc;
        this.c = tg;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final /* bridge */ /* synthetic */ Object zzb() {
        switch (this.a) {
            case 0:
                return new Ag((Dg) this.b.zzb(), this.c.a());
            default:
                return new Yn(0, (com.google.android.gms.common.util.a) this.b.zzb(), this.c.a());
        }
    }
}
