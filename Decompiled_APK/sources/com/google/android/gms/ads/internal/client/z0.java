package com.google.android.gms.ads.internal.client;

import android.os.RemoteException;

/* loaded from: classes2.dex */
public final class z0 extends com.google.android.gms.ads.d {
    public final Object b = new Object();
    public com.google.android.gms.ads.d c;
    public final /* synthetic */ A0 d;

    public z0(A0 a0) {
        this.d = a0;
    }

    @Override // com.google.android.gms.ads.d, com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        synchronized (this.b) {
            try {
                com.google.android.gms.ads.d dVar = this.c;
                if (dVar != null) {
                    dVar.onAdClicked();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdClosed() {
        synchronized (this.b) {
            try {
                com.google.android.gms.ads.d dVar = this.c;
                if (dVar != null) {
                    dVar.onAdClosed();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdFailedToLoad(com.google.android.gms.ads.l lVar) {
        A0 a0 = this.d;
        com.google.android.gms.ads.s sVar = a0.d;
        K k = a0.j;
        v0 v0VarK = null;
        if (k != null) {
            try {
                v0VarK = k.k();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
        sVar.b(v0VarK);
        synchronized (this.b) {
            try {
                com.google.android.gms.ads.d dVar = this.c;
                if (dVar != null) {
                    dVar.onAdFailedToLoad(lVar);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdImpression() {
        synchronized (this.b) {
            try {
                com.google.android.gms.ads.d dVar = this.c;
                if (dVar != null) {
                    dVar.onAdImpression();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdLoaded() {
        A0 a0 = this.d;
        com.google.android.gms.ads.s sVar = a0.d;
        K k = a0.j;
        v0 v0VarK = null;
        if (k != null) {
            try {
                v0VarK = k.k();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
        sVar.b(v0VarK);
        synchronized (this.b) {
            try {
                com.google.android.gms.ads.d dVar = this.c;
                if (dVar != null) {
                    dVar.onAdLoaded();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdOpened() {
        synchronized (this.b) {
            try {
                com.google.android.gms.ads.d dVar = this.c;
                if (dVar != null) {
                    dVar.onAdOpened();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
