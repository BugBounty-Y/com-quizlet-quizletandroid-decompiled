package com.google.android.gms.internal.ads;

import android.os.RemoteException;

/* renamed from: com.google.android.gms.internal.ads.jb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2225jb implements com.google.android.gms.ads.internal.overlay.j {
    public final /* synthetic */ zzbsd a;

    public C2225jb(zzbsd zzbsdVar) {
        this.a = zzbsdVar;
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void I3() {
        com.google.android.gms.ads.internal.util.client.i.d("Opening AdMobCustomTabsAdapter overlay.");
        C2326lq c2326lq = (C2326lq) this.a.b;
        c2326lq.getClass();
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdOpened.");
        try {
            ((InterfaceC1671Ca) c2326lq.b).o();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void L2() {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void X(int i) {
        com.google.android.gms.ads.internal.util.client.i.d("AdMobCustomTabsAdapter overlay is closed.");
        C2326lq c2326lq = (C2326lq) this.a.b;
        c2326lq.getClass();
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdClosed.");
        try {
            ((InterfaceC1671Ca) c2326lq.b).f();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void Y3() {
        com.google.android.gms.ads.internal.util.client.i.d("AdMobCustomTabsAdapter overlay is paused.");
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void f3() {
        com.google.android.gms.ads.internal.util.client.i.d("Delay close AdMobCustomTabsAdapter overlay.");
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void v3() {
        com.google.android.gms.ads.internal.util.client.i.d("AdMobCustomTabsAdapter overlay is resumed.");
    }
}
