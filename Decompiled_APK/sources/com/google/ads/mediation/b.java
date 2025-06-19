package com.google.ads.mediation;

import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.ads.l;
import com.google.android.gms.ads.mediation.h;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.C2326lq;
import com.google.android.gms.internal.ads.InterfaceC1671Ca;

/* loaded from: classes2.dex */
public final class b extends com.google.android.gms.ads.d implements com.google.android.gms.ads.admanager.a, InterfaceC1582a {
    public final h b;

    public b(AbstractAdViewAdapter abstractAdViewAdapter, h hVar) {
        this.b = hVar;
    }

    @Override // com.google.android.gms.ads.d, com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        C2326lq c2326lq = (C2326lq) this.b;
        c2326lq.getClass();
        u.d("#008 Must be called on the main UI thread.");
        i.d("Adapter called onAdClicked.");
        try {
            ((InterfaceC1671Ca) c2326lq.b).zze();
        } catch (RemoteException e) {
            i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdClosed() {
        C2326lq c2326lq = (C2326lq) this.b;
        c2326lq.getClass();
        u.d("#008 Must be called on the main UI thread.");
        i.d("Adapter called onAdClosed.");
        try {
            ((InterfaceC1671Ca) c2326lq.b).f();
        } catch (RemoteException e) {
            i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdFailedToLoad(l lVar) {
        ((C2326lq) this.b).c(lVar);
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdLoaded() {
        C2326lq c2326lq = (C2326lq) this.b;
        c2326lq.getClass();
        u.d("#008 Must be called on the main UI thread.");
        i.d("Adapter called onAdLoaded.");
        try {
            ((InterfaceC1671Ca) c2326lq.b).v();
        } catch (RemoteException e) {
            i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdOpened() {
        C2326lq c2326lq = (C2326lq) this.b;
        c2326lq.getClass();
        u.d("#008 Must be called on the main UI thread.");
        i.d("Adapter called onAdOpened.");
        try {
            ((InterfaceC1671Ca) c2326lq.b).o();
        } catch (RemoteException e) {
            i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.ads.admanager.a
    public final void onAppEvent(String str, String str2) {
        C2326lq c2326lq = (C2326lq) this.b;
        c2326lq.getClass();
        u.d("#008 Must be called on the main UI thread.");
        i.d("Adapter called onAppEvent.");
        try {
            ((InterfaceC1671Ca) c2326lq.b).T2(str, str2);
        } catch (RemoteException e) {
            i.j("#007 Could not call remote method.", e);
        }
    }
}
