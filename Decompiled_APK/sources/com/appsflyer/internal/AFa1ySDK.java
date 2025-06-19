package com.appsflyer.internal;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.appsflyer.AFLogger;
import com.appsflyer.AppsFlyerInAppPurchaseValidatorListener;
import com.appsflyer.AppsFlyerLib;
import com.appsflyer.attribution.AppsFlyerRequestListener;
import com.appsflyer.internal.AFe1lSDK.AnonymousClass5;
import com.appsflyer.internal.components.network.http.ResponseNetwork;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AFa1ySDK implements Runnable {
    private final String AFAdRevenueData;
    private final String areAllFieldsValid;
    private final Map<String, String> component1;
    private final String component3;
    final String getCurrencyIso4217Code;
    final String getMediationNetwork;
    private final WeakReference<Context> getMonetizationNetwork;
    final String getRevenue;

    public AFa1ySDK(Context context, String str, String str2, String str3, String str4, String str5, String str6, Map<String, String> map) {
        this.getMonetizationNetwork = new WeakReference<>(context);
        this.AFAdRevenueData = str;
        this.component3 = str2;
        this.getMediationNetwork = str4;
        this.getCurrencyIso4217Code = str5;
        this.getRevenue = str6;
        this.component1 = map;
        this.areAllFieldsValid = str3;
    }

    public static void getMediationNetwork(boolean z, String str, String str2, String str3, String str4) {
        if (AFa1tSDK.AFAdRevenueData != null) {
            StringBuilder sbH = AbstractC0147y.h("Validate callback parameters: ", str, " ", str2, " ");
            sbH.append(str3);
            AFLogger.afDebugLog(sbH.toString());
            if (z) {
                AFLogger.afDebugLog("Validate in app purchase success: ".concat(String.valueOf(str4)));
                AFa1tSDK.AFAdRevenueData.onValidateInApp();
                return;
            }
            AFLogger.afDebugLog("Validate in app purchase failed: ".concat(String.valueOf(str4)));
            AppsFlyerInAppPurchaseValidatorListener appsFlyerInAppPurchaseValidatorListener = AFa1tSDK.AFAdRevenueData;
            if (str4 == null) {
                str4 = "Failed validating";
            }
            appsFlyerInAppPurchaseValidatorListener.onValidateInAppFailure(str4);
        }
    }

    private static AFf1rSDK getRevenue(Context context, @NonNull AFh1hSDK aFh1hSDK) {
        ((AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).getMediationNetwork(context);
        AFc1dSDK aFc1dSDKAFAdRevenueData = ((AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).AFAdRevenueData();
        aFh1hSDK.AFAdRevenueData(aFc1dSDKAFAdRevenueData.getRevenue().getMonetizationNetwork.AFAdRevenueData("appsFlyerCount", 0));
        AFf1rSDK aFf1rSDK = new AFf1rSDK(aFh1hSDK, aFc1dSDKAFAdRevenueData);
        AFe1lSDK aFe1lSDKCopydefault = aFc1dSDKAFAdRevenueData.copydefault();
        aFe1lSDKCopydefault.getRevenue.execute(aFe1lSDKCopydefault.new AnonymousClass5(aFf1rSDK));
        return aFf1rSDK;
    }

    @Override // java.lang.Runnable
    public final void run() {
        String str = this.AFAdRevenueData;
        if (str == null || str.length() == 0 || AppsFlyerLib.getInstance().isStopped()) {
            return;
        }
        try {
            Context context = this.getMonetizationNetwork.get();
            if (context == null) {
                return;
            }
            HashMap map = new HashMap();
            map.put("public-key", this.component3);
            map.put("sig-data", this.getMediationNetwork);
            map.put("signature", this.areAllFieldsValid);
            Object map2 = new HashMap(map);
            Object obj = this.component1;
            String strAFAdRevenueData = ((AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).AFAdRevenueData().component2().AFAdRevenueData("referrer", "");
            AFi1zSDK aFi1zSDK = new AFi1zSDK();
            aFi1zSDK.component3 = strAFAdRevenueData;
            AFa1tSDK aFa1tSDK = (AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis());
            Map<String, Object> mediationNetwork = aFa1tSDK.getMediationNetwork(aFi1zSDK);
            mediationNetwork.put("price", this.getCurrencyIso4217Code);
            mediationNetwork.put("currency", this.getRevenue);
            mediationNetwork.put("receipt_data", map2);
            if (obj != null) {
                mediationNetwork.put("extra_prms", obj);
            }
            mediationNetwork.putAll(aFa1tSDK.AFAdRevenueData().registerClient().getCurrencyIso4217Code());
            aFi1zSDK.getMediationNetwork(mediationNetwork);
            getRevenue(context, aFi1zSDK);
            map.put("dev_key", this.AFAdRevenueData);
            map.put("app_id", context.getPackageName());
            map.put("uid", AppsFlyerLib.getInstance().getAppsFlyerUID(context));
            AFh1oSDK aFh1oSDK = ((AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).AFAdRevenueData().getRevenue().getCurrencyIso4217Code.component3;
            AFb1mSDK aFb1mSDK = aFh1oSDK != null ? new AFb1mSDK(aFh1oSDK.AFAdRevenueData, aFh1oSDK.getRevenue) : null;
            String str2 = aFb1mSDK != null ? aFb1mSDK.getMonetizationNetwork : null;
            if (str2 != null) {
                map.put("advertiserId", str2);
            }
            AFh1gSDK aFh1gSDK = (AFh1gSDK) new AFh1gSDK().getMediationNetwork(map);
            final AFf1rSDK revenue = getRevenue(context, aFh1gSDK);
            aFh1gSDK.getCurrencyIso4217Code = new AppsFlyerRequestListener() { // from class: com.appsflyer.internal.AFa1ySDK.5
                @Override // com.appsflyer.attribution.AppsFlyerRequestListener
                public final void onError(int i, @NonNull String str3) {
                    ResponseNetwork responseNetwork;
                    if (i == 50 && (responseNetwork = ((AFe1dSDK) revenue).component1) != null) {
                        str3 = responseNetwork.toString();
                    }
                    AFa1ySDK aFa1ySDK = AFa1ySDK.this;
                    AFa1ySDK.getMediationNetwork(false, aFa1ySDK.getMediationNetwork, aFa1ySDK.getCurrencyIso4217Code, aFa1ySDK.getRevenue, str3);
                }

                @Override // com.appsflyer.attribution.AppsFlyerRequestListener
                public final void onSuccess() {
                    try {
                        JSONObject jSONObject = new JSONObject((String) ((AFe1dSDK) revenue).component1.getBody());
                        AFLogger.afInfoLog("Validate response ok: ".concat(String.valueOf(jSONObject)));
                        boolean zOptBoolean = jSONObject.optBoolean("result");
                        AFa1ySDK aFa1ySDK = AFa1ySDK.this;
                        AFa1ySDK.getMediationNetwork(zOptBoolean, aFa1ySDK.getMediationNetwork, aFa1ySDK.getCurrencyIso4217Code, aFa1ySDK.getRevenue, jSONObject.toString());
                    } catch (Exception e) {
                        AFLogger.afErrorLog("Failed Validate request: ".concat(String.valueOf(e)), e);
                        AFa1ySDK aFa1ySDK2 = AFa1ySDK.this;
                        AFa1ySDK.getMediationNetwork(false, aFa1ySDK2.getMediationNetwork, aFa1ySDK2.getCurrencyIso4217Code, aFa1ySDK2.getRevenue, e.getMessage());
                    }
                }
            };
        } catch (Throwable th) {
            if (AFa1tSDK.AFAdRevenueData != null) {
                AFLogger.afErrorLog("Failed Validate request + ex", th);
                getMediationNetwork(false, this.getMediationNetwork, this.getCurrencyIso4217Code, this.getRevenue, th.getMessage());
            }
            AFLogger.afErrorLog(th.getMessage(), th);
        }
    }
}
