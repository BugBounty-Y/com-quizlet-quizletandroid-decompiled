package com.appsflyer.internal;

import android.content.Context;
import androidx.annotation.NonNull;
import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final class AFk1rSDK {
    public final WeakReference<Context> AFAdRevenueData;
    public String getMonetizationNetwork;

    public AFk1rSDK(@NonNull Context context) {
        this.AFAdRevenueData = new WeakReference<>(context);
    }
}
