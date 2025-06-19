package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.zzm;

/* loaded from: classes2.dex */
public final class Xk implements Rk {
    public final long a;
    public final S4 b;
    public final Sp c;

    public Xk(long j, Context context, S4 s4, C1765Re c1765Re, String str) {
        this.a = j;
        this.b = s4;
        this.c = (Sp) ((BC) new C1732Mb(c1765Re.b, context, str).c).zzb();
    }

    @Override // com.google.android.gms.internal.ads.Rk
    public final void a() {
        try {
            Sp sp = this.c;
            sp.R0(new Wk(this));
            sp.D(new com.google.android.gms.dynamic.b(null));
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.Rk
    public final void b(zzm zzmVar) {
        try {
            this.c.Z2(zzmVar, new Vk(this));
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.Rk
    public final void zza() {
    }
}
