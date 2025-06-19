package com.appsflyer.internal;

import android.app.Activity;
import android.app.Application;
import android.content.Context;

/* loaded from: classes.dex */
public enum AFh1tSDK {
    application,
    activity,
    other;

    public static AFh1tSDK getRevenue(Context context) {
        return context instanceof Activity ? activity : context instanceof Application ? application : other;
    }
}
