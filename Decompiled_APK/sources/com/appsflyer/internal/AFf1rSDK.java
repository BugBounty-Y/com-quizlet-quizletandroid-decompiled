package com.appsflyer.internal;

import androidx.annotation.NonNull;
import com.appsflyer.AFLogger;
import com.appsflyer.attribution.AppsFlyerRequestListener;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import kotlin.text.StringsKt;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class AFf1rSDK extends AFe1dSDK<String> {
    private static final AFe1mSDK[] AFInAppEventType = {AFe1mSDK.DLSDK, AFe1mSDK.ONELINK, AFe1mSDK.REGISTER};
    private final AFf1dSDK AFKeystoreWrapper;
    private final AFc1iSDK AFLogger;
    public final AFh1rSDK component2;
    protected final AFc1qSDK copy;

    @NonNull
    private final AFc1pSDK copydefault;
    private final AFe1zSDK equals;
    private final AFf1oSDK hashCode;
    protected final AFg1qSDK toString;

    public AFf1rSDK(@NonNull AFh1rSDK aFh1rSDK, @NonNull AFc1dSDK aFc1dSDK) {
        this(aFh1rSDK, aFc1dSDK, null);
    }

    @NonNull
    public static Map<String, Object> component1(AFh1rSDK aFh1rSDK) {
        Map<String, Object> map = (Map) aFh1rSDK.AFAdRevenueData.get("meta");
        if (map != null) {
            return map;
        }
        HashMap map2 = new HashMap();
        aFh1rSDK.AFAdRevenueData.put("meta", map2);
        return map2;
    }

    public void AFAdRevenueData(AFh1rSDK aFh1rSDK) {
        try {
            try {
                getCurrencyIso4217Code(aFh1rSDK);
                getRevenue(aFh1rSDK);
                getMediationNetwork(aFh1rSDK);
                getMonetizationNetwork(aFh1rSDK);
                component3(aFh1rSDK);
            } catch (Throwable th) {
                AFLogger.INSTANCE.e(AFg1cSDK.QUEUE, "Error while collecting payload params", th, true, true, false);
            }
            if (aFh1rSDK.getRevenue()) {
                aFh1rSDK.getMediationNetwork(((AFe1dSDK) this).component3.AFAdRevenueData(aFh1rSDK.AFAdRevenueData));
                aFh1rSDK.getMediationNetwork(((AFe1dSDK) this).component3.getMonetizationNetwork(aFh1rSDK.AFAdRevenueData));
                if (this.copydefault.getMonetizationNetwork("com.appsflyer.security.enable", false)) {
                    AFf1gSDK.getCurrencyIso4217Code(new Object[]{aFh1rSDK}, -211782083, 211782085, (int) System.currentTimeMillis());
                }
            }
            if (aFh1rSDK.component2()) {
                aFh1rSDK.getMediationNetwork(((AFe1dSDK) this).component3.getCurrencyIso4217Code());
            }
            Set<AFe1mSDK> set = this.getCurrencyIso4217Code;
            boolean z = set.contains(AFe1mSDK.LAUNCH) || set.contains(AFe1mSDK.CONVERSION);
            if (areAllFieldsValid() && z) {
                aFh1rSDK.AFAdRevenueData(this.copy.AFAdRevenueData("appsFlyerCount", 0));
            }
            if (aFh1rSDK.areAllFieldsValid()) {
                Map<String, Object> mapComponent1 = component1(aFh1rSDK);
                AFe1zSDK aFe1zSDK = this.equals;
                AFe1xSDK aFe1xSDK = new AFe1xSDK(aFe1zSDK.getMediationNetwork(), aFe1zSDK.getCurrencyIso4217Code(), AFe1zSDK.AFAdRevenueData() ? AFe1wSDK.DEFAULT : AFe1wSDK.API);
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("name", aFe1xSDK.getMediationNetwork);
                AFe1wSDK aFe1wSDK = aFe1xSDK.AFAdRevenueData;
                if (aFe1wSDK != AFe1wSDK.DEFAULT) {
                    jSONObject.put("method", aFe1wSDK.getCurrencyIso4217Code);
                }
                String str = aFe1xSDK.getRevenue;
                if (str != null && !StringsKt.O(str)) {
                    jSONObject.put("prefix", aFe1xSDK.getRevenue);
                }
                mapComponent1.put("host", jSONObject);
            }
            if (this.copydefault.getMonetizationNetwork("AF_PREINSTALL_DISABLED", false)) {
                component1(aFh1rSDK).put("preinstall_disabled", Boolean.TRUE);
            }
            this.AFKeystoreWrapper.AFAdRevenueData(aFh1rSDK.AFAdRevenueData, aFh1rSDK.getCurrencyIso4217Code());
        } catch (Throwable th2) {
            AFLogger.INSTANCE.e(AFg1cSDK.QUEUE, "Error while preparing to send event", th2, true, true, false);
        }
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final AppsFlyerRequestListener component3() {
        return this.component2.getCurrencyIso4217Code;
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public boolean copydefault() {
        return true;
    }

    public void getCurrencyIso4217Code(AFh1rSDK aFh1rSDK) {
        this.toString.getMediationNetwork(aFh1rSDK);
    }

    public void getMediationNetwork(AFh1rSDK aFh1rSDK) {
        this.toString.getMonetizationNetwork(aFh1rSDK);
    }

    public void getMonetizationNetwork(AFh1rSDK aFh1rSDK) {
        this.toString.getRevenue(aFh1rSDK);
    }

    /* JADX WARN: Removed duplicated region for block: B:63:0x0120  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0127  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0142  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0159  */
    @Override // com.appsflyer.internal.AFe1dSDK
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.appsflyer.internal.AFd1nSDK<java.lang.String> getRevenue(@androidx.annotation.NonNull java.lang.String r20) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 355
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFf1rSDK.getRevenue(java.lang.String):com.appsflyer.internal.AFd1nSDK");
    }

    public AFf1rSDK(@NonNull AFh1rSDK aFh1rSDK, @NonNull AFc1dSDK aFc1dSDK, String str) {
        super(aFh1rSDK.getCurrencyIso4217Code(), new AFe1mSDK[]{AFe1mSDK.RC_CDN, AFe1mSDK.FETCH_ADVERTISING_ID}, aFc1dSDK, str);
        this.component2 = aFh1rSDK;
        this.equals = aFc1dSDK.AFKeystoreWrapper();
        this.copy = aFc1dSDK.component2();
        this.hashCode = aFc1dSDK.component1();
        this.AFLogger = aFc1dSDK.AFInAppEventType();
        this.copydefault = aFc1dSDK.getRevenue();
        this.toString = aFc1dSDK.component3();
        this.AFKeystoreWrapper = aFc1dSDK.afErrorLog();
        for (AFe1mSDK aFe1mSDK : AFInAppEventType) {
            if (this.getMonetizationNetwork == aFe1mSDK) {
                return;
            }
        }
        int i = this.component2.component2;
        AFe1mSDK aFe1mSDK2 = this.getMonetizationNetwork;
        if (i > 0) {
            this.AFAdRevenueData.add(AFe1mSDK.CONVERSION);
        } else {
            AFe1mSDK aFe1mSDK3 = AFe1mSDK.CONVERSION;
            if (aFe1mSDK2 != aFe1mSDK3) {
                this.getCurrencyIso4217Code.add(aFe1mSDK3);
            }
        }
    }

    public void component3(AFh1rSDK aFh1rSDK) {
        this.toString.AFAdRevenueData(aFh1rSDK);
    }

    public void getRevenue(AFh1rSDK aFh1rSDK) {
        this.toString.getRevenue(aFh1rSDK.AFAdRevenueData);
    }
}
