package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Dm implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final C1741Ne c;
    public final Tg d;
    public final BC e;
    public final DC f;
    public final BC g;
    public final BC h;
    public final BC i;
    public final BC j;

    public /* synthetic */ Dm(BC bc, C1741Ne c1741Ne, Tg tg, BC bc2, DC dc, BC bc3, BC bc4, BC bc5, BC bc6, int i) {
        this.a = i;
        this.b = bc;
        this.c = c1741Ne;
        this.d = tg;
        this.e = bc2;
        this.f = dc;
        this.g = bc3;
        this.h = bc4;
        this.i = bc5;
        this.j = bc6;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new Cm((C1777Te) this.f.a, (Context) this.b.zzb(), (Executor) this.e.zzb(), (C2406nk) this.g.zzb(), this.d.a(), this.c.b(), new C2475p9(), (BinderC2408nm) this.h.zzb(), (Ek) this.i.zzb(), (Hk) this.j.zzb());
            case 1:
                return new Um((Context) this.b.zzb(), this.c.b(), this.d.a(), (Executor) this.e.zzb(), (C1813Ze) this.f.a, (C2406nk) this.g.zzb(), new C2475p9(), (BinderC2408nm) this.h.zzb(), (Ek) this.i.zzb(), (Hk) this.j.zzb());
            default:
                return new Um((Context) this.b.zzb(), this.c.b(), this.d.a(), (Executor) this.e.zzb(), (C1882bf) this.f.a, (C2406nk) this.g.zzb(), new C2475p9(), (BinderC2408nm) this.h.zzb(), (Ek) this.i.zzb(), (Hk) this.j.zzb());
        }
    }

    public Dm(DC dc, BC bc, BC bc2, BC bc3, Tg tg, C1741Ne c1741Ne, BC bc4, BC bc5, BC bc6) {
        this.a = 0;
        this.f = dc;
        this.b = bc;
        this.e = bc2;
        this.g = bc3;
        this.d = tg;
        this.c = c1741Ne;
        this.h = bc4;
        this.i = bc5;
        this.j = bc6;
    }
}
