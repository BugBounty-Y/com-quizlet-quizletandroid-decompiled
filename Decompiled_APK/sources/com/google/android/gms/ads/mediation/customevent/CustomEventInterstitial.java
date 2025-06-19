package com.google.android.gms.ads.mediation.customevent;

import android.content.Context;
import android.os.Bundle;
import androidx.annotation.NonNull;

@Deprecated
/* loaded from: classes2.dex */
public interface CustomEventInterstitial extends a {
    /* synthetic */ void onDestroy();

    /* synthetic */ void onPause();

    /* synthetic */ void onResume();

    void requestInterstitialAd(@NonNull Context context, @NonNull c cVar, String str, @NonNull com.google.android.gms.ads.mediation.d dVar, Bundle bundle);

    void showInterstitial();
}
