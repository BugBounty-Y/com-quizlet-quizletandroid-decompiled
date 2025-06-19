package com.appsflyer.internal;

import android.content.Intent;
import android.net.Uri;

/* loaded from: classes.dex */
public final class AFb1rSDK {
    public static Uri j_(Intent intent) {
        if (intent == null) {
            return null;
        }
        AFj1jSDK aFj1jSDK = new AFj1jSDK(intent);
        Uri uri = (Uri) aFj1jSDK.H_("android.intent.extra.REFERRER");
        if (uri != null) {
            return uri;
        }
        String revenue = aFj1jSDK.getRevenue("android.intent.extra.REFERRER_NAME");
        if (revenue != null) {
            return Uri.parse(revenue);
        }
        return null;
    }
}
