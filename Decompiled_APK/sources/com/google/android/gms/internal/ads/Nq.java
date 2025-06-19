package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class Nq implements InterfaceC2015ei, InterfaceC2102gh, InterfaceC2103gi {
    public final Tq a;
    public final Pq b;

    public Nq(Context context, Tq tq) {
        this.a = tq;
        this.b = LA.f(context, 13);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2103gi
    public final void a() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2103gi
    public final void b() {
        if (((Boolean) R7.d.o()).booleanValue()) {
            Pq pq = this.b;
            pq.h(true);
            this.a.a(pq);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2015ei
    public final void i() {
        if (((Boolean) R7.d.o()).booleanValue()) {
            this.b.zzi();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2102gh
    public final void r(zze zzeVar) {
        if (((Boolean) R7.d.o()).booleanValue()) {
            String string = zzeVar.a().toString();
            Pq pq = this.b;
            pq.A(string);
            pq.h(false);
            this.a.a(pq);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2015ei
    public final void zzi() {
    }
}
