package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.yr, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2885yr implements CC {
    public final /* synthetic */ int a;
    public final BC b;

    public /* synthetic */ C2885yr(BC bc, int i) {
        this.a = i;
        this.b = bc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        BC bc = this.b;
        switch (this.a) {
            case 0:
                return new BinderC2842xr((C2928zr) bc.zzb());
            default:
                C2318li c2318li = new C2318li((Cg) bc.zzb(), AbstractC2270kd.g);
                int i = AbstractC2459ou.c;
                return new Nu(c2318li);
        }
    }
}
