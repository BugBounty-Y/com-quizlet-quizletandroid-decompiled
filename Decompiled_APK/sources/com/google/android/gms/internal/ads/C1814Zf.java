package com.google.android.gms.internal.ads;

import android.content.Context;

/* renamed from: com.google.android.gms.internal.ads.Zf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1814Zf implements CC {
    public final /* synthetic */ int a = 1;
    public final BC b;
    public final C1741Ne c;
    public final C2702ug d;
    public final Tg e;

    public C1814Zf(BC bc, C1741Ne c1741Ne, C2702ug c2702ug, Tg tg) {
        this.b = bc;
        this.c = c1741Ne;
        this.d = c2702ug;
        this.e = tg;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new C2318li(new C1790Vf((Context) this.b.zzb(), this.c.b(), this.d.a(), this.e.a(), 0), AbstractC2270kd.g);
            default:
                return new C2318li(new C1790Vf((Context) this.b.zzb(), this.c.b(), this.d.a(), this.e.a(), 1), AbstractC2270kd.g);
        }
    }

    public C1814Zf(com.google.firebase.messaging.u uVar, BC bc, C1741Ne c1741Ne, C2702ug c2702ug, Tg tg) {
        this.b = bc;
        this.c = c1741Ne;
        this.d = c2702ug;
        this.e = tg;
    }
}
