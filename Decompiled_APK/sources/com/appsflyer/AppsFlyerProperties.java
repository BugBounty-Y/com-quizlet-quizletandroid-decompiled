package com.appsflyer;

import com.appsflyer.AFLogger;
import com.appsflyer.internal.AFc1qSDK;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class AppsFlyerProperties {
    public static final String ADDITIONAL_CUSTOM_DATA = "additionalCustomData";
    public static final String AF_STORE_FROM_API = "api_store_value";
    public static final String AF_WAITFOR_CUSTOMERID = "waitForCustomerId";
    public static final String APP_ID = "appid";
    public static final String APP_USER_ID = "AppUserId";
    public static final String CHANNEL = "channel";
    public static final String COLLECT_ANDROID_ID = "collectAndroidId";
    public static final String COLLECT_ANDROID_ID_FORCE_BY_USER = "collectAndroidIdForceByUser";
    public static final String COLLECT_FACEBOOK_ATTR_ID = "collectFacebookAttrId";
    public static final String COLLECT_IMEI = "collectIMEI";
    public static final String COLLECT_IMEI_FORCE_BY_USER = "collectIMEIForceByUser";
    public static final String COLLECT_OAID = "collectOAID";
    public static final String CURRENCY_CODE = "currencyCode";
    public static final String DEVICE_TRACKING_DISABLED = "deviceTrackingDisabled";
    public static final String DISABLE_KEYSTORE = "keyPropDisableAFKeystore";
    public static final String DISABLE_LOGS_COMPLETELY = "disableLogs";
    public static final String DISABLE_NETWORK_DATA = "disableCollectNetworkData";
    public static final String DISABLE_OTHER_SDK = "disableOtherSdk";
    public static final String DPM = "disableProxy";
    public static final String EMAIL_CRYPT_TYPE = "userEmailsCryptType";
    public static final String ENABLE_GPS_FALLBACK = "enableGpsFallback";
    public static final String ENABLE_TCF_DATA_COLLECTION = "enableTCFDataCollection";
    public static final String EXTENSION = "sdkExtension";
    public static final String HTTP_CACHE = "http_cache";
    public static final String IS_UPDATE = "IS_UPDATE";
    public static final String LAUNCH_PROTECT_ENABLED = "launchProtectEnabled";
    public static final String NEW_REFERRER_SENT = "newGPReferrerSent";
    public static final String ONELINK_DOMAIN = "onelinkDomain";
    public static final String ONELINK_ID = "oneLinkSlug";
    public static final String ONELINK_SCHEME = "onelinkScheme";
    public static final String ONELINK_VERSION = "onelinkVersion";
    public static final String USER_EMAILS = "userEmails";
    public static AppsFlyerProperties instance;
    public boolean getCurrencyIso4217Code;
    public String getMediationNetwork;
    private final Map<String, Object> getRevenue = new HashMap();
    private boolean AFAdRevenueData = false;

    public enum EmailsCryptType {
        NONE(0),
        SHA256(3);

        private final int getRevenue;

        EmailsCryptType(int i) {
            this.getRevenue = i;
        }

        public final int getValue() {
            return this.getRevenue;
        }
    }

    private boolean getCurrencyIso4217Code() {
        return this.AFAdRevenueData;
    }

    public static AppsFlyerProperties getInstance() {
        if (instance == null) {
            instance = new AppsFlyerProperties();
        }
        return instance;
    }

    public final boolean AFAdRevenueData() {
        return this.getCurrencyIso4217Code;
    }

    public boolean getBoolean(String str, boolean z) {
        String string = getString(str);
        return string == null ? z : Boolean.parseBoolean(string);
    }

    public int getInt(String str, int i) {
        String string = getString(str);
        return string == null ? i : Integer.parseInt(string);
    }

    public int getLogLevel() {
        return getInt("logLevel", AFLogger.LogLevel.NONE.getLevel());
    }

    public long getLong(String str, long j) {
        String string = getString(str);
        return string == null ? j : Long.parseLong(string);
    }

    public String getReferrer(AFc1qSDK aFc1qSDK) {
        String str = this.getMediationNetwork;
        return str != null ? str : getString("AF_REFERRER") != null ? getString("AF_REFERRER") : aFc1qSDK.AFAdRevenueData("referrer", (String) null);
    }

    public synchronized String getString(String str) {
        return (String) this.getRevenue.get(str);
    }

    public boolean isEnableLog() {
        return getLogLevel() > AFLogger.LogLevel.NONE.getLevel();
    }

    public boolean isLogsDisabledCompletely() {
        return getBoolean(DISABLE_LOGS_COMPLETELY, false);
    }

    public boolean isOtherSdkStringDisabled() {
        return getBoolean(DISABLE_OTHER_SDK, false);
    }

    public synchronized void loadProperties(AFc1qSDK aFc1qSDK) {
        try {
            if (getCurrencyIso4217Code()) {
                return;
            }
            String strAFAdRevenueData = aFc1qSDK.AFAdRevenueData("savedProperties", (String) null);
            if (strAFAdRevenueData != null) {
                AFLogger.afDebugLog("Loading properties..");
                try {
                    JSONObject jSONObject = new JSONObject(strAFAdRevenueData);
                    Iterator<String> itKeys = jSONObject.keys();
                    while (itKeys.hasNext()) {
                        String next = itKeys.next();
                        if (this.getRevenue.get(next) == null) {
                            this.getRevenue.put(next, jSONObject.getString(next));
                        }
                    }
                    String[] strArr = {"AppsFlyerKey", "custom_host", "custom_host_prefix", "advertiserIdEnabled", "advertiserId"};
                    for (int i = 0; i < 5; i++) {
                        this.getRevenue.remove(strArr[i]);
                    }
                    saveProperties(aFc1qSDK);
                    this.AFAdRevenueData = true;
                } catch (JSONException e) {
                    AFLogger.afErrorLog("Failed loading properties", e);
                }
                StringBuilder sb = new StringBuilder("Done loading properties: ");
                sb.append(this.AFAdRevenueData);
                AFLogger.afDebugLog(sb.toString());
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public synchronized void remove(String str) {
        this.getRevenue.remove(str);
    }

    public synchronized void saveProperties(AFc1qSDK aFc1qSDK) {
        this.getRevenue.remove("AppsFlyerKey");
        aFc1qSDK.getMediationNetwork("savedProperties", new JSONObject(this.getRevenue).toString());
    }

    public synchronized void set(String str, String str2) {
        this.getRevenue.put(str, str2);
    }

    public synchronized void setCustomData(String str) {
        this.getRevenue.put(ADDITIONAL_CUSTOM_DATA, str);
    }

    public synchronized void setUserEmails(String str) {
        this.getRevenue.put(USER_EMAILS, str);
    }

    public synchronized void set(String str, String[] strArr) {
        this.getRevenue.put(str, strArr);
    }

    public synchronized void set(String str, int i) {
        this.getRevenue.put(str, Integer.toString(i));
    }

    public synchronized void set(String str, long j) {
        this.getRevenue.put(str, Long.toString(j));
    }

    public synchronized void set(String str, boolean z) {
        this.getRevenue.put(str, Boolean.toString(z));
    }
}
