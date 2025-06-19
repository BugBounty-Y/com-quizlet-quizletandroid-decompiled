package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import com.google.android.gms.common.ConnectionResult;

/* loaded from: classes2.dex */
public final class Jl extends Hl {
    public String g;
    public int h;

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public final void X() {
        synchronized (this.b) {
            try {
                if (!this.d) {
                    this.d = true;
                    try {
                        try {
                            int i = this.h;
                            if (i == 2) {
                                ((InterfaceC1774Tb) this.f.m()).x3(this.e, ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Rc)).booleanValue() ? new Gl(this.a, this.e) : new Fl(this));
                            } else if (i == 3) {
                                ((InterfaceC1774Tb) this.f.m()).M1(this.g, ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Rc)).booleanValue() ? new Gl(this.a, this.e) : new Fl(this));
                            } else {
                                this.a.d(new zzdyq(1));
                            }
                        } catch (Throwable th) {
                            com.google.android.gms.ads.internal.j.C.h.h("RemoteUrlAndCacheKeyClientTask.onConnected", th);
                            this.a.d(new zzdyq(1));
                        }
                    } catch (RemoteException | IllegalArgumentException unused) {
                        this.a.d(new zzdyq(1));
                    }
                }
            } catch (Throwable th2) {
                throw th2;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Hl, com.google.android.gms.common.internal.InterfaceC1653c
    public final void f0(ConnectionResult connectionResult) {
        com.google.android.gms.ads.internal.util.client.i.d("Cannot connect to remote service, fallback to local instance.");
        this.a.d(new zzdyq(1));
    }
}
