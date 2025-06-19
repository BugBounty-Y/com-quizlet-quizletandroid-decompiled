package com.google.ads.mediation;

import android.os.RemoteException;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.ads.mediation.l;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.BinderC2707ul;
import com.google.android.gms.internal.ads.C2326lq;
import com.google.android.gms.internal.ads.InterfaceC1671Ca;
import com.google.android.gms.internal.ads.Os;

/* loaded from: classes2.dex */
public final class d extends com.google.android.gms.ads.d {
    public final /* synthetic */ int b = 0;
    public final Object c;
    public final Object d;

    public d(AbstractAdViewAdapter abstractAdViewAdapter, l lVar) {
        this.c = abstractAdViewAdapter;
        this.d = lVar;
    }

    private final void a() {
    }

    @Override // com.google.android.gms.ads.d, com.google.android.gms.ads.internal.client.InterfaceC1582a
    public void onAdClicked() {
        switch (this.b) {
            case 0:
                C2326lq c2326lq = (C2326lq) ((l) this.d);
                c2326lq.getClass();
                u.d("#008 Must be called on the main UI thread.");
                a aVar = (a) c2326lq.c;
                if (((Os) c2326lq.d) == null) {
                    if (aVar != null) {
                        if (!aVar.n) {
                            i.d("Could not call onAdClicked since setOverrideClickHandling is not set to true");
                            break;
                        }
                    } else {
                        i.j("#007 Could not call remote method.", null);
                        break;
                    }
                }
                i.d("Adapter called onAdClicked.");
                try {
                    ((InterfaceC1671Ca) c2326lq.b).zze();
                    break;
                } catch (RemoteException e) {
                    i.j("#007 Could not call remote method.", e);
                    return;
                }
        }
    }

    @Override // com.google.android.gms.ads.d
    public void onAdClosed() {
        switch (this.b) {
            case 0:
                C2326lq c2326lq = (C2326lq) ((l) this.d);
                c2326lq.getClass();
                u.d("#008 Must be called on the main UI thread.");
                i.d("Adapter called onAdClosed.");
                try {
                    ((InterfaceC1671Ca) c2326lq.b).f();
                    break;
                } catch (RemoteException e) {
                    i.j("#007 Could not call remote method.", e);
                    return;
                }
        }
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdFailedToLoad(com.google.android.gms.ads.l lVar) {
        switch (this.b) {
            case 0:
                ((C2326lq) ((l) this.d)).g(lVar);
                break;
            default:
                ((BinderC2707ul) this.d).i4(BinderC2707ul.h4(lVar), (String) this.c);
                break;
        }
    }

    @Override // com.google.android.gms.ads.d
    public void onAdImpression() {
        switch (this.b) {
            case 0:
                C2326lq c2326lq = (C2326lq) ((l) this.d);
                c2326lq.getClass();
                u.d("#008 Must be called on the main UI thread.");
                a aVar = (a) c2326lq.c;
                if (((Os) c2326lq.d) == null) {
                    if (aVar != null) {
                        if (!aVar.m) {
                            i.d("Could not call onAdImpression since setOverrideImpressionRecording is not set to true");
                            break;
                        }
                    } else {
                        i.j("#007 Could not call remote method.", null);
                        break;
                    }
                }
                i.d("Adapter called onAdImpression.");
                try {
                    ((InterfaceC1671Ca) c2326lq.b).l();
                    break;
                } catch (RemoteException e) {
                    i.j("#007 Could not call remote method.", e);
                    return;
                }
        }
    }

    @Override // com.google.android.gms.ads.d
    public void onAdLoaded() {
        int i = this.b;
    }

    @Override // com.google.android.gms.ads.d
    public void onAdOpened() {
        switch (this.b) {
            case 0:
                C2326lq c2326lq = (C2326lq) ((l) this.d);
                c2326lq.getClass();
                u.d("#008 Must be called on the main UI thread.");
                i.d("Adapter called onAdOpened.");
                try {
                    ((InterfaceC1671Ca) c2326lq.b).o();
                    break;
                } catch (RemoteException e) {
                    i.j("#007 Could not call remote method.", e);
                    return;
                }
        }
    }

    public d(BinderC2707ul binderC2707ul, String str) {
        this.c = str;
        this.d = binderC2707ul;
    }
}
