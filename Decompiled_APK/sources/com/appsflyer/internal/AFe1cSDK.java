package com.appsflyer.internal;

import androidx.annotation.NonNull;
import com.appsflyer.PurchaseHandler;
import java.util.Map;

/* loaded from: classes.dex */
public final class AFe1cSDK extends AFe1iSDK {
    public AFe1cSDK(@NonNull Map<String, Object> map, PurchaseHandler.PurchaseValidationCallback purchaseValidationCallback, @NonNull AFc1dSDK aFc1dSDK) {
        super(AFe1mSDK.PURCHASE_VALIDATE, new AFe1mSDK[]{AFe1mSDK.RC_CDN, AFe1mSDK.FETCH_ADVERTISING_ID}, aFc1dSDK, map, purchaseValidationCallback);
        this.AFAdRevenueData.add(AFe1mSDK.CONVERSION);
    }

    @Override // com.appsflyer.internal.AFe1gSDK
    public final AFd1nSDK<String> AFAdRevenueData(@NonNull Map<String, Object> map, @NonNull String str, String str2) {
        return this.component4.getCurrencyIso4217Code(map, str, str2);
    }
}
