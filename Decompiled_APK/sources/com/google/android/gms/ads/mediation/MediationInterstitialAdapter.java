package com.google.android.gms.ads.mediation;

import android.content.Context;
import android.os.Bundle;
import androidx.annotation.NonNull;

@Deprecated
/* loaded from: classes2.dex */
public interface MediationInterstitialAdapter extends e {
    /* synthetic */ void onDestroy();

    /* synthetic */ void onPause();

    /* synthetic */ void onResume();

    void requestInterstitialAd(@NonNull Context context, @NonNull j jVar, @NonNull Bundle bundle, @NonNull d dVar, Bundle bundle2);

    void showInterstitial();
}
