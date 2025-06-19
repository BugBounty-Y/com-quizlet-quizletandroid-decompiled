package com.google.android.gms.ads.mediation;

import android.content.Context;
import android.os.RemoteException;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.r;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class a {
    @NonNull
    public abstract r getSDKVersionInfo();

    @NonNull
    public abstract r getVersionInfo();

    public abstract void initialize(@NonNull Context context, @NonNull b bVar, @NonNull List<com.google.android.material.shape.e> list);

    public void loadAppOpenAd(@NonNull f fVar, @NonNull c cVar) {
        cVar.s(new com.google.android.gms.ads.b(7, getClass().getSimpleName().concat(" does not support app open ads."), "com.google.android.gms.ads", null));
    }

    public void loadBannerAd(@NonNull g gVar, @NonNull c cVar) {
        cVar.s(new com.google.android.gms.ads.b(7, getClass().getSimpleName().concat(" does not support banner ads."), "com.google.android.gms.ads", null));
    }

    public void loadInterstitialAd(@NonNull i iVar, @NonNull c cVar) {
        cVar.s(new com.google.android.gms.ads.b(7, getClass().getSimpleName().concat(" does not support interstitial ads."), "com.google.android.gms.ads", null));
    }

    @Deprecated
    public void loadNativeAd(@NonNull k kVar, @NonNull c cVar) {
        cVar.s(new com.google.android.gms.ads.b(7, getClass().getSimpleName().concat(" does not support native ads."), "com.google.android.gms.ads", null));
    }

    public void loadNativeAdMapper(@NonNull k kVar, @NonNull c cVar) throws RemoteException {
        throw new RemoteException("Method is not found");
    }

    public void loadRewardedAd(@NonNull m mVar, @NonNull c cVar) {
        cVar.s(new com.google.android.gms.ads.b(7, getClass().getSimpleName().concat(" does not support rewarded ads."), "com.google.android.gms.ads", null));
    }

    public void loadRewardedInterstitialAd(@NonNull m mVar, @NonNull c cVar) {
        cVar.s(new com.google.android.gms.ads.b(7, getClass().getSimpleName().concat(" does not support rewarded interstitial ads."), "com.google.android.gms.ads", null));
    }
}
