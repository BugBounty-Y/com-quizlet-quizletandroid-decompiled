package com.google.ads.mediation;

import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.BinderC1617s;
import com.google.android.gms.ads.internal.client.K;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.ads.l;
import com.google.android.gms.ads.mediation.j;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.C2326lq;
import com.google.android.gms.internal.ads.InterfaceC1671Ca;
import com.google.android.gms.internal.ads.Q9;

/* loaded from: classes2.dex */
public final class c extends com.google.android.gms.ads.interstitial.b {
    public final AbstractAdViewAdapter c;
    public final j d;

    public c(AbstractAdViewAdapter abstractAdViewAdapter, j jVar) {
        this.c = abstractAdViewAdapter;
        this.d = jVar;
    }

    @Override // com.google.android.gms.ads.w
    public final void a(l lVar) {
        ((C2326lq) this.d).f(lVar);
    }

    @Override // com.google.android.gms.ads.w
    public final void b(Object obj) {
        com.google.android.gms.ads.interstitial.a aVar = (com.google.android.gms.ads.interstitial.a) obj;
        AbstractAdViewAdapter abstractAdViewAdapter = this.c;
        abstractAdViewAdapter.mInterstitialAd = aVar;
        j jVar = this.d;
        com.google.android.gms.internal.instantapps.a aVar2 = new com.google.android.gms.internal.instantapps.a(22, abstractAdViewAdapter, jVar);
        Q9 q9 = (Q9) aVar;
        q9.getClass();
        try {
            K k = q9.c;
            if (k != null) {
                k.M0(new BinderC1617s(aVar2));
            }
        } catch (RemoteException e) {
            i.j("#007 Could not call remote method.", e);
        }
        C2326lq c2326lq = (C2326lq) jVar;
        c2326lq.getClass();
        u.d("#008 Must be called on the main UI thread.");
        i.d("Adapter called onAdLoaded.");
        try {
            ((InterfaceC1671Ca) c2326lq.b).v();
        } catch (RemoteException e2) {
            i.j("#007 Could not call remote method.", e2);
        }
    }
}
