package com.appsflyer.internal;

import android.app.Activity;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public interface AFi1kSDK {
    String getCurrencyIso4217Code(Activity activity);

    void getMediationNetwork(@NotNull Activity activity);

    @NotNull
    String getMonetizationNetwork(Activity activity);
}
