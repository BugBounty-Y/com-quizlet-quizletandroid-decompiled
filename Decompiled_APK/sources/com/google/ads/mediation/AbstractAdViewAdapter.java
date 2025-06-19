package com.google.ads.mediation;

import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import android.view.View;
import androidx.annotation.NonNull;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.AdRequest$Builder;
import com.google.android.gms.ads.e;
import com.google.android.gms.ads.f;
import com.google.android.gms.ads.g;
import com.google.android.gms.ads.i;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.K;
import com.google.android.gms.ads.internal.client.v0;
import com.google.android.gms.ads.mediation.MediationBannerAdapter;
import com.google.android.gms.ads.mediation.MediationInterstitialAdapter;
import com.google.android.gms.ads.mediation.MediationNativeAdapter;
import com.google.android.gms.ads.mediation.h;
import com.google.android.gms.ads.mediation.j;
import com.google.android.gms.ads.s;
import com.google.android.gms.internal.ads.Q9;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes2.dex */
public abstract class AbstractAdViewAdapter implements MediationBannerAdapter, MediationInterstitialAdapter, MediationNativeAdapter {

    @NonNull
    public static final String AD_UNIT_ID_PARAMETER = "pubid";
    private f adLoader;

    @NonNull
    protected i mAdView;

    @NonNull
    protected com.google.android.gms.ads.interstitial.a mInterstitialAd;

    public g buildAdRequest(Context context, com.google.android.gms.ads.mediation.d dVar, Bundle bundle, Bundle bundle2) {
        AdRequest$Builder adRequest$Builder = new AdRequest$Builder();
        Set setD = dVar.d();
        if (setD != null) {
            Iterator it2 = setD.iterator();
            while (it2.hasNext()) {
                adRequest$Builder.addKeyword((String) it2.next());
            }
        }
        if (dVar.c()) {
            com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
            adRequest$Builder.zza(com.google.android.gms.ads.internal.util.client.c.o(context));
        }
        if (dVar.a() != -1) {
            adRequest$Builder.zzd(dVar.a() == 1);
        }
        adRequest$Builder.zzb(dVar.b());
        adRequest$Builder.addNetworkExtrasBundle(AdMobAdapter.class, buildExtrasBundle(bundle, bundle2));
        return new g(adRequest$Builder);
    }

    public abstract Bundle buildExtrasBundle(Bundle bundle, Bundle bundle2);

    @NonNull
    public String getAdUnitId(@NonNull Bundle bundle) {
        return bundle.getString(AD_UNIT_ID_PARAMETER);
    }

    @Override // com.google.android.gms.ads.mediation.MediationBannerAdapter
    @NonNull
    public View getBannerView() {
        return this.mAdView;
    }

    public com.google.android.gms.ads.interstitial.a getInterstitialAd() {
        return this.mInterstitialAd;
    }

    public v0 getVideoController() {
        v0 v0Var;
        i iVar = this.mAdView;
        if (iVar == null) {
            return null;
        }
        s sVarA = iVar.a();
        synchronized (sVarA.a) {
            v0Var = sVarA.b;
        }
        return v0Var;
    }

    public e newAdLoader(Context context, String str) {
        return new e(context, str);
    }

    @Override // com.google.android.gms.ads.mediation.MediationBannerAdapter, com.google.android.gms.ads.mediation.e, com.google.android.gms.ads.mediation.MediationInterstitialAdapter, com.google.android.gms.ads.mediation.MediationNativeAdapter
    public void onDestroy() {
        i iVar = this.mAdView;
        if (iVar != null) {
            iVar.destroy();
            this.mAdView = null;
        }
        if (this.mInterstitialAd != null) {
            this.mInterstitialAd = null;
        }
        if (this.adLoader != null) {
            this.adLoader = null;
        }
    }

    public void onImmersiveModeUpdated(boolean z) {
        com.google.android.gms.ads.interstitial.a aVar = this.mInterstitialAd;
        if (aVar != null) {
            try {
                K k = ((Q9) aVar).c;
                if (k != null) {
                    k.c3(z);
                }
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
    }

    @Override // com.google.android.gms.ads.mediation.MediationBannerAdapter, com.google.android.gms.ads.mediation.e, com.google.android.gms.ads.mediation.MediationInterstitialAdapter, com.google.android.gms.ads.mediation.MediationNativeAdapter
    public void onPause() {
        i iVar = this.mAdView;
        if (iVar != null) {
            iVar.pause();
        }
    }

    @Override // com.google.android.gms.ads.mediation.MediationBannerAdapter, com.google.android.gms.ads.mediation.e, com.google.android.gms.ads.mediation.MediationInterstitialAdapter, com.google.android.gms.ads.mediation.MediationNativeAdapter
    public void onResume() {
        i iVar = this.mAdView;
        if (iVar != null) {
            iVar.resume();
        }
    }

    @Override // com.google.android.gms.ads.mediation.MediationBannerAdapter
    public void requestBannerAd(@NonNull Context context, @NonNull h hVar, @NonNull Bundle bundle, @NonNull com.google.android.gms.ads.h hVar2, @NonNull com.google.android.gms.ads.mediation.d dVar, @NonNull Bundle bundle2) {
        i iVar = new i(context);
        this.mAdView = iVar;
        iVar.setAdSize(new com.google.android.gms.ads.h(hVar2.a, hVar2.b));
        this.mAdView.setAdUnitId(getAdUnitId(bundle));
        this.mAdView.setAdListener(new b(this, hVar));
        this.mAdView.loadAd(buildAdRequest(context, dVar, bundle2, bundle));
    }

    @Override // com.google.android.gms.ads.mediation.MediationInterstitialAdapter
    public void requestInterstitialAd(@NonNull Context context, @NonNull j jVar, @NonNull Bundle bundle, @NonNull com.google.android.gms.ads.mediation.d dVar, @NonNull Bundle bundle2) {
        com.google.android.gms.ads.interstitial.a.a(context, getAdUnitId(bundle), buildAdRequest(context, dVar, bundle2, bundle), new c(this, jVar));
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00b5  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x0148  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0130 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // com.google.android.gms.ads.mediation.MediationNativeAdapter
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void requestNativeAd(@androidx.annotation.NonNull android.content.Context r28, @androidx.annotation.NonNull com.google.android.gms.ads.mediation.l r29, @androidx.annotation.NonNull android.os.Bundle r30, @androidx.annotation.NonNull com.google.android.gms.ads.mediation.n r31, @androidx.annotation.NonNull android.os.Bundle r32) {
        /*
            Method dump skipped, instructions count: 415
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.ads.mediation.AbstractAdViewAdapter.requestNativeAd(android.content.Context, com.google.android.gms.ads.mediation.l, android.os.Bundle, com.google.android.gms.ads.mediation.n, android.os.Bundle):void");
    }

    @Override // com.google.android.gms.ads.mediation.MediationInterstitialAdapter
    public void showInterstitial() {
        com.google.android.gms.ads.interstitial.a aVar = this.mInterstitialAd;
        if (aVar != null) {
            aVar.b(null);
        }
    }
}
