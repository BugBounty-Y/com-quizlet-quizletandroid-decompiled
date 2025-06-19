package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.nj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2405nj implements CC {
    public final /* synthetic */ int a = 1;
    public final BC b;
    public final Mi c;

    public C2405nj(Mi mi, BC bc) {
        this.c = mi;
        this.b = bc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                C1843ak c1843ak = (C1843ak) this.c.b.b;
                AbstractC1981ds.s(c1843ak);
                return new ViewOnClickListenerC2362mj(c1843ak, (com.google.android.gms.common.util.a) this.b.zzb());
            default:
                C2406nk c2406nk = (C2406nk) this.b.zzb();
                C1843ak c1843ak2 = (C1843ak) this.c.b.b;
                AbstractC1981ds.s(c1843ak2);
                return new C2662tj(c2406nk, c1843ak2);
        }
    }

    public C2405nj(BC bc, Mi mi) {
        this.b = bc;
        this.c = mi;
    }
}
