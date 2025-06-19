package com.google.android.gms.ads.mediation.customevent;

import android.content.Context;
import android.os.Bundle;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.h;

@Deprecated
/* loaded from: classes2.dex */
public interface CustomEventBanner extends a {
    /* synthetic */ void onDestroy();

    /* synthetic */ void onPause();

    /* synthetic */ void onResume();

    void requestBannerAd(@NonNull Context context, @NonNull b bVar, String str, @NonNull h hVar, @NonNull com.google.android.gms.ads.mediation.d dVar, Bundle bundle);
}
