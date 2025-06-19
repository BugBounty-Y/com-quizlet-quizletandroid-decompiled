package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.zp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2926zp implements InterfaceC2544qt {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2326lq b;

    public /* synthetic */ C2926zp(C2326lq c2326lq, int i) {
        this.a = i;
        this.b = c2326lq;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
    public final /* bridge */ /* synthetic */ Object apply(Object obj) {
        switch (this.a) {
            case 0:
                com.google.android.gms.ads.internal.util.client.i.f("", (zzdyq) obj);
                com.google.android.gms.ads.internal.util.A.l("Failed to get a cache key, reverting to legacy flow.");
                C2326lq c2326lq = this.b;
                Ap ap = new Ap(null, c2326lq.x());
                c2326lq.d = ap;
                return ap;
            default:
                zzbvl zzbvlVar = (zzbvl) obj;
                Ap ap2 = new Ap(zzbvlVar, new C2884yq(zzbvlVar.j));
                this.b.d = ap2;
                return ap2;
        }
    }
}
