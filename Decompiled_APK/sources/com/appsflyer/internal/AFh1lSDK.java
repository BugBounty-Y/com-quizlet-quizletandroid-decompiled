package com.appsflyer.internal;

import androidx.annotation.NonNull;
import com.appsflyer.AFAdRevenueData;
import java.util.Map;

/* loaded from: classes.dex */
public final class AFh1lSDK extends AFh1rSDK {
    public final Map<String, Object> copy;

    @NonNull
    public final AFAdRevenueData equals;

    public AFh1lSDK(@NonNull AFAdRevenueData aFAdRevenueData, Map<String, Object> map) {
        super("adrevenue_generic", null, Boolean.TRUE);
        this.equals = aFAdRevenueData;
        this.copy = map;
    }

    @Override // com.appsflyer.internal.AFh1rSDK
    public final AFe1mSDK getCurrencyIso4217Code() {
        return AFe1mSDK.ADREVENUE;
    }
}
