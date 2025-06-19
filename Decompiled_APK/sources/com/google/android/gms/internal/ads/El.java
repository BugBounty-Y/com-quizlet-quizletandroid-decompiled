package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.common.ConnectionResult;

/* loaded from: classes2.dex */
public final class El extends Hl {
    public final /* synthetic */ int g;
    public final Context h;
    public final Xv i;

    public El(Context context, Xv xv, int i) {
        this.g = i;
        switch (i) {
            case 1:
                this.h = context;
                this.i = xv;
                this.f = new C2172i6(context, com.google.android.gms.ads.internal.j.C.t.o(), (Hl) this, (Hl) this);
                break;
            default:
                this.h = context;
                this.i = xv;
                this.f = new C2172i6(context, com.google.android.gms.ads.internal.j.C.t.o(), (Hl) this, (Hl) this);
                break;
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public final void X() {
        switch (this.g) {
            case 0:
                synchronized (this.b) {
                    try {
                        if (!this.d) {
                            this.d = true;
                            try {
                                try {
                                    ((InterfaceC1774Tb) this.f.m()).E0(this.e, ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Rc)).booleanValue() ? new Gl(this.a, this.e) : new Fl(this));
                                } catch (RemoteException | IllegalArgumentException unused) {
                                    this.a.d(new zzdyq(1));
                                }
                            } catch (Throwable th) {
                                com.google.android.gms.ads.internal.j.C.h.h("RemoteAdRequestClientTask.onConnected", th);
                                this.a.d(new zzdyq(1));
                            }
                        }
                    } catch (Throwable th2) {
                        throw th2;
                    }
                }
                return;
            default:
                synchronized (this.b) {
                    try {
                        if (!this.d) {
                            this.d = true;
                            try {
                                ((InterfaceC1774Tb) this.f.m()).h1(this.e, ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Rc)).booleanValue() ? new Gl(this.a, this.e) : new Fl(this));
                            } catch (RemoteException | IllegalArgumentException unused2) {
                                this.a.d(new zzdyq(1));
                            } catch (Throwable th3) {
                                com.google.android.gms.ads.internal.j.C.h.h("RemoteSignalsClientTask.onConnected", th3);
                                this.a.d(new zzdyq(1));
                            }
                        }
                    } catch (Throwable th4) {
                        throw th4;
                    }
                }
                return;
        }
    }

    public com.google.common.util.concurrent.e c(zzbvl zzbvlVar) {
        synchronized (this.b) {
            try {
                if (this.c) {
                    return this.a;
                }
                this.c = true;
                this.e = zzbvlVar;
                this.f.c();
                C2313ld c2313ld = this.a;
                c2313ld.a.a(new RunnableC2104gj(this, 4), AbstractC2270kd.g);
                Hl.b(this.h, c2313ld, this.i);
                return c2313ld;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Hl, com.google.android.gms.common.internal.InterfaceC1653c
    public void f0(ConnectionResult connectionResult) {
        switch (this.g) {
            case 0:
                com.google.android.gms.ads.internal.util.client.i.d("Cannot connect to remote service, fallback to local instance.");
                this.a.d(new zzdyq(1));
                break;
            default:
                super.f0(connectionResult);
                break;
        }
    }
}
