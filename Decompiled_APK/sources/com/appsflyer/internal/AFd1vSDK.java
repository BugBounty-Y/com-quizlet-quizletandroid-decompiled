package com.appsflyer.internal;

import androidx.annotation.NonNull;

/* loaded from: classes.dex */
public interface AFd1vSDK {

    public interface AFa1ySDK {
        void onConfigurationChanged(boolean z);
    }

    void AFAdRevenueData();

    void AFAdRevenueData(AFa1ySDK aFa1ySDK);

    void getCurrencyIso4217Code();

    void getMediationNetwork(@NonNull Throwable th, @NonNull String str);
}
