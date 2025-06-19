package com.google.android.gms.ads;

import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.A0;
import com.google.android.gms.ads.internal.client.K;
import com.google.android.gms.internal.ads.C1744Ob;

/* loaded from: classes2.dex */
public final /* synthetic */ class u implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ k b;

    public /* synthetic */ u(k kVar, int i) {
        this.a = i;
        this.b = kVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                k kVar = this.b;
                try {
                    A0 a0 = kVar.zza;
                    a0.getClass();
                    try {
                        K k = a0.j;
                        if (k != null) {
                            k.K();
                            break;
                        }
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
                        return;
                    }
                } catch (IllegalStateException e2) {
                    C1744Ob.a(kVar.getContext()).d("BaseAdView.resume", e2);
                    return;
                }
                break;
            case 1:
                k kVar2 = this.b;
                try {
                    A0 a02 = kVar2.zza;
                    a02.getClass();
                    try {
                        K k2 = a02.j;
                        if (k2 != null) {
                            k2.y();
                        }
                    } catch (RemoteException e3) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
                    }
                    break;
                } catch (IllegalStateException e4) {
                    C1744Ob.a(kVar2.getContext()).d("BaseAdView.destroy", e4);
                    return;
                }
            default:
                k kVar3 = this.b;
                try {
                    A0 a03 = kVar3.zza;
                    a03.getClass();
                    try {
                        K k3 = a03.j;
                        if (k3 != null) {
                            k3.P();
                            break;
                        }
                    } catch (RemoteException e5) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e5);
                        return;
                    }
                } catch (IllegalStateException e6) {
                    C1744Ob.a(kVar3.getContext()).d("BaseAdView.pause", e6);
                }
                break;
        }
    }
}
