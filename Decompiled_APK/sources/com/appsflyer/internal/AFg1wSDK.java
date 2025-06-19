package com.appsflyer.internal;

import android.annotation.SuppressLint;

/* loaded from: classes.dex */
public final class AFg1wSDK extends AFh1rSDK {
    @SuppressLint({"VisibleForTests"})
    public AFg1wSDK() {
        super("Register", null, Boolean.FALSE);
    }

    @Override // com.appsflyer.internal.AFh1rSDK
    public final AFe1mSDK getCurrencyIso4217Code() {
        return AFe1mSDK.REGISTER;
    }

    @Override // com.appsflyer.internal.AFh1rSDK
    public final boolean getRevenue() {
        return false;
    }
}
