package com.appsflyer.internal;

import androidx.annotation.NonNull;
import com.appsflyer.PurchaseHandler;
import com.appsflyer.internal.components.network.http.ResponseNetwork;
import java.util.Map;

/* loaded from: classes.dex */
public final class AFe1hSDK extends AFe1iSDK {
    public AFe1hSDK(@NonNull Map<String, Object> map, PurchaseHandler.PurchaseValidationCallback purchaseValidationCallback, @NonNull AFc1dSDK aFc1dSDK) {
        super(AFe1mSDK.ARS_VALIDATE, new AFe1mSDK[]{AFe1mSDK.RC_CDN, AFe1mSDK.FETCH_ADVERTISING_ID}, aFc1dSDK, map, purchaseValidationCallback);
        this.AFAdRevenueData.add(AFe1mSDK.CONVERSION);
    }

    @Override // com.appsflyer.internal.AFe1gSDK
    public final AFd1nSDK<String> AFAdRevenueData(@NonNull Map<String, Object> map, @NonNull String str, String str2) {
        return this.component4.AFAdRevenueData(map, str, str2);
    }

    @Override // com.appsflyer.internal.AFe1iSDK, com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final boolean getMediationNetwork() {
        ResponseNetwork responseNetwork = ((AFe1dSDK) this).component1;
        if (responseNetwork == null || responseNetwork.getStatusCode() != 424) {
            return super.getMediationNetwork();
        }
        return true;
    }
}
