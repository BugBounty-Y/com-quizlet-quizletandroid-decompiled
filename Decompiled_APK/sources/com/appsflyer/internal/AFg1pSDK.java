package com.appsflyer.internal;

import androidx.annotation.NonNull;
import com.appsflyer.AFInAppEventParameterName;
import com.appsflyer.AFLogger;
import com.appsflyer.attribution.AppsFlyerRequestListener;
import com.appsflyer.internal.components.network.http.ResponseNetwork;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AFg1pSDK extends AFe1dSDK<Map<String, Object>> {
    private static final List<String> component2 = Arrays.asList("googleplay", "playstore", "googleplaystore");
    private String AFInAppEventParameterName;
    private Map<String, Object> copy;
    private final AFh1vSDK copydefault;
    private final AFc1pSDK equals;
    private final AFd1oSDK hashCode;
    private final AFc1qSDK toString;

    public AFg1pSDK(@NonNull AFc1dSDK aFc1dSDK) {
        super(AFe1mSDK.GCDSDK, new AFe1mSDK[]{AFe1mSDK.RC_CDN}, aFc1dSDK, "GCD-FETCH");
        this.hashCode = aFc1dSDK.getCurrencyIso4217Code();
        this.toString = aFc1dSDK.component2();
        this.copydefault = aFc1dSDK.areAllFieldsValid();
        this.equals = aFc1dSDK.getRevenue();
        this.AFAdRevenueData.add(AFe1mSDK.CONVERSION);
        this.AFAdRevenueData.add(AFe1mSDK.LAUNCH);
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final AppsFlyerRequestListener component3() {
        return null;
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final boolean copydefault() {
        return false;
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    @NonNull
    public final AFe1rSDK getCurrencyIso4217Code() throws Exception {
        AFe1rSDK currencyIso4217Code;
        AFe1rSDK aFe1rSDK;
        if (((AFe1dSDK) this).component3.AFAdRevenueData()) {
            AFLogger.afDebugLog("[GCD-E03] 'isStopTracking' enabled");
            this.AFInAppEventParameterName = "'isStopTracking' enabled";
            throw new AFe1oSDK();
        }
        AFe1rSDK aFe1rSDK2 = AFe1rSDK.FAILURE;
        int i = 0;
        while (i <= 2) {
            boolean z = true;
            boolean z2 = i >= 2;
            this.copydefault.equals = System.currentTimeMillis();
            try {
                try {
                    currencyIso4217Code = super.getCurrencyIso4217Code();
                    ResponseNetwork responseNetwork = ((AFe1dSDK) this).component1;
                    if (responseNetwork != null) {
                        int statusCode = responseNetwork.getStatusCode();
                        if (statusCode != 403 && statusCode < 500) {
                            z = false;
                        }
                        if (responseNetwork.isSuccessful() || statusCode == 404) {
                            Map<String, Object> map = (Map) responseNetwork.getBody();
                            int statusCode2 = responseNetwork.getStatusCode();
                            Boolean bool = (Boolean) map.get("iscache");
                            if (statusCode2 == 404) {
                                map.remove("error_reason");
                                map.remove("status_code");
                                map.put("af_status", "Organic");
                                map.put("af_message", "organic install");
                            }
                            if (bool != null && !bool.booleanValue()) {
                                this.toString.getMonetizationNetwork("appsflyerConversionDataCacheExpiration", System.currentTimeMillis());
                            }
                            if (map.containsKey("af_siteid")) {
                                if (map.containsKey(AFInAppEventParameterName.AF_CHANNEL)) {
                                    StringBuilder sb = new StringBuilder("[Invite] Detected App-Invite via channel: ");
                                    sb.append(map.get(AFInAppEventParameterName.AF_CHANNEL));
                                    AFLogger.afDebugLog(sb.toString());
                                } else {
                                    AFLogger.afDebugLog(String.format("[CrossPromotion] App was installed via %s's Cross Promotion", map.get("af_siteid")));
                                }
                            }
                            map.put("is_first_launch", Boolean.FALSE);
                            this.toString.getMediationNetwork("attributionId", new JSONObject(map).toString());
                            if (!this.toString.getMediationNetwork("sixtyDayConversionData", false)) {
                                map.put("is_first_launch", Boolean.TRUE);
                            }
                            this.copy = map;
                            aFe1rSDK = AFe1rSDK.SUCCESS;
                        } else {
                            if (!z2) {
                                if (!z) {
                                }
                            }
                            this.AFInAppEventParameterName = "Error connection to server: ".concat(String.valueOf(statusCode));
                            aFe1rSDK = AFe1rSDK.FAILURE;
                        }
                        return aFe1rSDK;
                    }
                } catch (AFe1nSDK e) {
                    AFLogger.afDebugLog("[GCD-E05] AppsFlyer dev key is missing");
                    this.AFInAppEventParameterName = "AppsFlyer dev key is missing";
                    throw e;
                } catch (Exception e2) {
                    StringBuilder sb2 = new StringBuilder("[GCD] Error: ");
                    sb2.append(e2.getMessage());
                    AFLogger.afErrorLog(sb2.toString(), e2, false, false);
                    currencyIso4217Code = AFe1rSDK.FAILURE;
                    if (z2) {
                        this.AFInAppEventParameterName = e2.getMessage();
                        throw e2;
                    }
                }
                aFe1rSDK2 = currencyIso4217Code;
                i++;
            } finally {
                this.copydefault.AFAdRevenueData(i);
                AFLogger.afDebugLog("[GCD-A03] Server retrieving attempt finished");
            }
        }
        return aFe1rSDK2;
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final boolean getMediationNetwork() {
        return false;
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final void getRevenue() {
        super.getRevenue();
        Map<String, Object> map = this.copy;
        String str = this.AFInAppEventParameterName;
        if (map != null) {
            AFg1nSDK.getMonetizationNetwork(map);
        } else if (str == null || str.isEmpty()) {
            AFg1nSDK.getMediationNetwork("Unknown error");
        } else {
            AFg1nSDK.getMediationNetwork(str);
        }
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final AFd1nSDK<Map<String, Object>> getRevenue(@NonNull String str) {
        String strConcat;
        String monetizationNetwork = AFa1tSDK.getMonetizationNetwork(this.toString, this.equals.component2());
        if (monetizationNetwork != null && !monetizationNetwork.trim().isEmpty()) {
            if (!component2.contains(monetizationNetwork.toLowerCase(Locale.getDefault()))) {
                strConcat = "-".concat(monetizationNetwork);
            } else {
                AFLogger.afWarnLog("[GCD] AF detected using redundant Google-Play channel for attribution - " + monetizationNetwork + ". Using without channel postfix.");
                strConcat = "";
            }
        } else {
            strConcat = "";
        }
        AFd1nSDK<Map<String, Object>> revenue = this.hashCode.getRevenue(strConcat, str);
        StringBuilder sb = new StringBuilder("[GCD-B01] URL: ");
        sb.append(revenue.getRevenue.getMonetizationNetwork);
        AFLogger.afInfoLog(sb.toString());
        return revenue;
    }
}
