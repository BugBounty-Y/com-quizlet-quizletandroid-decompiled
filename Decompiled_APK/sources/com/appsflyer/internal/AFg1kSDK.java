package com.appsflyer.internal;

import android.content.Context;

/* loaded from: classes.dex */
public final class AFg1kSDK {
    public static boolean getMediationNetwork(Context context) {
        return context.getPackageManager().isInstantApp();
    }
}
