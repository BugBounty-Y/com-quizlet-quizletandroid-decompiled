package com.google.android.gms.ads.mediation;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.annotation.NonNull;

@Deprecated
/* loaded from: classes2.dex */
public interface MediationBannerAdapter extends e {
    @NonNull
    View getBannerView();

    @Override // com.google.android.gms.ads.mediation.e, com.google.android.gms.ads.mediation.MediationInterstitialAdapter, com.google.android.gms.ads.mediation.MediationNativeAdapter
    /* synthetic */ void onDestroy();

    @Override // com.google.android.gms.ads.mediation.e, com.google.android.gms.ads.mediation.MediationInterstitialAdapter, com.google.android.gms.ads.mediation.MediationNativeAdapter
    /* synthetic */ void onPause();

    @Override // com.google.android.gms.ads.mediation.e, com.google.android.gms.ads.mediation.MediationInterstitialAdapter, com.google.android.gms.ads.mediation.MediationNativeAdapter
    /* synthetic */ void onResume();

    void requestBannerAd(@NonNull Context context, @NonNull h hVar, @NonNull Bundle bundle, @NonNull com.google.android.gms.ads.h hVar2, @NonNull d dVar, Bundle bundle2);
}
