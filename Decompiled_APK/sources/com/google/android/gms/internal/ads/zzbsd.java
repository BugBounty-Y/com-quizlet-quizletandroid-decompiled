package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.RemoteException;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.overlay.zzc;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.mediation.MediationInterstitialAdapter;

/* loaded from: classes2.dex */
public final class zzbsd implements MediationInterstitialAdapter {
    public Activity a;
    public com.google.android.gms.ads.mediation.j b;
    public Uri c;

    @Override // com.google.android.gms.ads.mediation.MediationInterstitialAdapter, com.google.android.gms.ads.mediation.MediationNativeAdapter
    public final void onDestroy() {
        com.google.android.gms.ads.internal.util.client.i.d("Destroying AdMobCustomTabsAdapter adapter.");
    }

    @Override // com.google.android.gms.ads.mediation.MediationInterstitialAdapter, com.google.android.gms.ads.mediation.MediationNativeAdapter
    public final void onPause() {
        com.google.android.gms.ads.internal.util.client.i.d("Pausing AdMobCustomTabsAdapter adapter.");
    }

    @Override // com.google.android.gms.ads.mediation.MediationInterstitialAdapter, com.google.android.gms.ads.mediation.MediationNativeAdapter
    public final void onResume() {
        com.google.android.gms.ads.internal.util.client.i.d("Resuming AdMobCustomTabsAdapter adapter.");
    }

    @Override // com.google.android.gms.ads.mediation.MediationInterstitialAdapter
    public final void requestInterstitialAd(Context context, com.google.android.gms.ads.mediation.j jVar, Bundle bundle, com.google.android.gms.ads.mediation.d dVar, Bundle bundle2) {
        this.b = jVar;
        if (jVar == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Listener not set for mediation. Returning.");
            return;
        }
        if (!(context instanceof Activity)) {
            com.google.android.gms.ads.internal.util.client.i.h("AdMobCustomTabs can only work with Activity context. Bailing out.");
            ((C2326lq) this.b).a();
            return;
        }
        if (!G7.a(context)) {
            com.google.android.gms.ads.internal.util.client.i.h("Default browser does not support custom tabs. Bailing out.");
            ((C2326lq) this.b).a();
            return;
        }
        String string = bundle.getString("tab_url");
        if (TextUtils.isEmpty(string)) {
            com.google.android.gms.ads.internal.util.client.i.h("The tab_url retrieved from mediation metadata is empty. Bailing out.");
            ((C2326lq) this.b).a();
            return;
        }
        this.a = (Activity) context;
        this.c = Uri.parse(string);
        C2326lq c2326lq = (C2326lq) this.b;
        c2326lq.getClass();
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdLoaded.");
        try {
            ((InterfaceC1671Ca) c2326lq.b).v();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.ads.mediation.MediationInterstitialAdapter
    public final void showInterstitial() {
        androidx.work.impl.model.c cVarC = new androidx.browser.customtabs.k(0, false).c();
        ((Intent) cVarC.b).setData(this.c);
        boolean z = false;
        com.google.android.gms.ads.internal.util.F.l.post(new Qv(this, z, new AdOverlayInfoParcel(new zzc((Intent) cVarC.b, null), null, new C2225jb(this), null, new VersionInfoParcel(0, 0, false, false), null, null, ""), 9));
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        C1967dd c1967dd = jVar.h.l;
        c1967dd.getClass();
        jVar.k.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        synchronized (c1967dd.a) {
            try {
                if (c1967dd.c == 3) {
                    if (c1967dd.b + ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U5)).longValue() <= jCurrentTimeMillis) {
                        c1967dd.c = 1;
                    }
                }
            } finally {
            }
        }
        jVar.k.getClass();
        long jCurrentTimeMillis2 = System.currentTimeMillis();
        synchronized (c1967dd.a) {
            try {
                if (c1967dd.c != 2) {
                    return;
                }
                c1967dd.c = 3;
                if (c1967dd.c == 3) {
                    c1967dd.b = jCurrentTimeMillis2;
                }
            } finally {
            }
        }
    }
}
