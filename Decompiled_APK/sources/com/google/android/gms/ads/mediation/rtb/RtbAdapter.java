package com.google.android.gms.ads.mediation.rtb;

import android.os.RemoteException;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.mediation.c;
import com.google.android.gms.ads.mediation.f;
import com.google.android.gms.ads.mediation.g;
import com.google.android.gms.ads.mediation.i;
import com.google.android.gms.ads.mediation.k;
import com.google.android.gms.ads.mediation.m;

/* loaded from: classes2.dex */
public abstract class RtbAdapter extends com.google.android.gms.ads.mediation.a {
    public abstract void collectSignals(@NonNull a aVar, @NonNull b bVar);

    public void loadRtbAppOpenAd(@NonNull f fVar, @NonNull c cVar) {
        loadAppOpenAd(fVar, cVar);
    }

    public void loadRtbBannerAd(@NonNull g gVar, @NonNull c cVar) {
        loadBannerAd(gVar, cVar);
    }

    public void loadRtbInterstitialAd(@NonNull i iVar, @NonNull c cVar) {
        loadInterstitialAd(iVar, cVar);
    }

    @Deprecated
    public void loadRtbNativeAd(@NonNull k kVar, @NonNull c cVar) {
        loadNativeAd(kVar, cVar);
    }

    public void loadRtbNativeAdMapper(@NonNull k kVar, @NonNull c cVar) throws RemoteException {
        loadNativeAdMapper(kVar, cVar);
    }

    public void loadRtbRewardedAd(@NonNull m mVar, @NonNull c cVar) {
        loadRewardedAd(mVar, cVar);
    }

    public void loadRtbRewardedInterstitialAd(@NonNull m mVar, @NonNull c cVar) {
        loadRewardedInterstitialAd(mVar, cVar);
    }
}
