package com.amazon.device.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import androidx.camera.camera2.internal.RunnableC0131h;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3550w;
import java.security.SecureRandom;
import java.util.HashMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/* loaded from: classes.dex */
public class DtbDeviceRegistration {
    private static final String AAX_VIDEO_HOST_NAME_KEY = "aaxVideoHostname";
    private static final String CONFIG_OS_KEY = "os";
    private static final String CONFIG_OS_VERSION_KEY = "osVersion";
    private static final String CONFIG_PRIVACY_APPLICABLE = "privacyApplicable";
    private static final String CONFIG_PRIVACY_KEY = "privacy";
    private static final String CONFIG_SEGMENT_ID_KEY = "segmentId";
    private static final String LOG_TAG = "com.amazon.device.ads.DtbDeviceRegistration";
    private static String appId;
    private static int configSeq;
    private static DtbDeviceRegistration dtbDeviceRegistrationInstance;
    private final DtbMetrics metrics = new DtbMetrics();

    private DtbDeviceRegistration() {
    }

    private HashMap<String, Object> buildConfigInfoParams(String str) {
        HashMap<String, Object> map = new HashMap<>();
        map.put("appId", str);
        map.put("sdkVer", DtbCommonUtils.getSDKVersion());
        map.put("fp", "false");
        map.put("testMode", Boolean.toString(AdRegistration.isTestMode()));
        JSONObject paramsJsonGetSafe = DtbDeviceData.getDeviceDataInstance().getParamsJsonGetSafe();
        if (paramsJsonGetSafe != null) {
            map.put("dinfo", paramsJsonGetSafe);
        }
        JSONObject paramsJson = DtbPackageNativeData.getPackageNativeDataInstance(AdRegistration.getContext()).getParamsJson();
        if (paramsJson != null) {
            map.put("pkg", paramsJson);
        }
        if (AdRegistration.getCustomDictionary() != null && AdRegistration.getCustomDictionary().containsKey(DtbConstants.MEDIATION_NAME)) {
            String str2 = AdRegistration.getCustomDictionary().get(DtbConstants.MEDIATION_NAME);
            if (!DtbCommonUtils.isNullOrEmpty(str2)) {
                map.put(DtbConstants.MEDIATION_NAME, str2);
            }
        }
        if (Math.random() <= DTBMetricsConfiguration.getClientConfigVal("distribution_pixel", DTBMetricsConfiguration.DISTRIBUTION_PIXEL_DEFAULT_VALUE.intValue(), "sample_rates").intValue() / 100.0f) {
            String sDKDistributionPlace = AdRegistration.getSDKDistributionPlace();
            if (!DtbCommonUtils.isNullOrEmpty(sDKDistributionPlace)) {
                map.put("distribution", sDKDistributionPlace);
            }
        }
        map.put(CONFIG_SEGMENT_ID_KEY, Integer.valueOf(new SecureRandom().nextInt(1000) + 1));
        map.put(CONFIG_OS_KEY, DtbConstants.NATIVE_OS_NAME);
        map.put("osVersion", Build.VERSION.RELEASE);
        return map;
    }

    private HashMap<String, Object> buildSISParams(String str) {
        HashMap<String, Object> map = new HashMap<>(DtbDeviceData.getDeviceDataInstance().getDeviceParams());
        String adId = DtbSharedPreferences.getInstance().getAdId();
        if (adId != null) {
            map.put("adId", adId);
        }
        String idfa = DtbSharedPreferences.getInstance().getIdfa();
        Boolean optOut = DtbSharedPreferences.getInstance().getOptOut();
        if (!DtbCommonUtils.isNullOrEmpty(idfa)) {
            map.put("idfa", idfa);
        }
        map.put("oo", convertBooleanToFlag(optOut));
        if (str != null) {
            map.put("appId", str);
        }
        JSONObject paramsJson = DtbPackageNativeData.getPackageNativeDataInstance(AdRegistration.getContext()).getParamsJson();
        if (paramsJson != null) {
            map.put("pkg", paramsJson);
        }
        Context context = AdRegistration.getContext();
        if (context != null) {
            SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
            Object obj = defaultSharedPreferences.contains("IABTCF_gdprApplies") ? defaultSharedPreferences.getAll().get("IABTCF_gdprApplies") : null;
            String string = defaultSharedPreferences.getString("IABTCF_TCString", null);
            if (obj != null) {
                try {
                    if ((obj instanceof Integer) && (((Integer) obj).intValue() == 1 || ((Integer) obj).intValue() == 0)) {
                        map.put("gdpr", obj);
                    } else if (((obj instanceof String) && ((String) obj).equals("1")) || ((String) obj).equals("0")) {
                        map.put("gdpr", obj);
                    } else {
                        DtbLog.info("IABTCF_gdprApplies should be a 1 or 0 as per IAB guideline");
                    }
                } catch (ClassCastException unused) {
                    DtbLog.info("IABTCF_gdprApplies should be a number as per IAB guideline");
                }
            }
            if (string != null) {
                map.put("gdpr_consent", string);
            }
            if (DTBMetricsConfiguration.getInstance().isFeatureEnabled(DTBMetricsConfiguration.FEATURE_FLAG_GPP_PARAMS_TO_AIP_CALL)) {
                HashMap<String, Object> mapAddGPPParametersFromPreferences = DtbCommonUtils.addGPPParametersFromPreferences(defaultSharedPreferences);
                if (!DtbCommonUtils.isNullOrEmpty(mapAddGPPParametersFromPreferences)) {
                    map.putAll(mapAddGPPParametersFromPreferences);
                }
            }
        }
        String encodedNonIABString = AdRegistration.getEncodedNonIABString();
        if (!DtbCommonUtils.isNullOrEmpty(encodedNonIABString)) {
            map.put("gdpr_custom", encodedNonIABString);
        }
        return map;
    }

    private static String convertBooleanToFlag(Boolean bool) {
        return (bool != null && bool.booleanValue()) ? "1" : "0";
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v7 */
    private synchronized void initializeAds() {
        DtbMetric dtbMetric;
        DtbMetric dtbMetric2;
        JSONObject jSONObject;
        DtbMetric dtbMetric3 = "ad id failed registration: ";
        synchronized (this) {
            if (DtbCommonUtils.isOnMainThread()) {
                DtbLog.error(LOG_TAG, "Unable to fetch advertising identifier information on main thread.");
                return;
            }
            String appKey = AdRegistration.getAppKey();
            appId = appKey;
            if (DtbCommonUtils.isNullOrEmpty(appKey)) {
                DtbLog.error(LOG_TAG, "App id not available");
                return;
            }
            if (!DtbCommonUtils.isNetworkConnected()) {
                DtbLog.debug("Network is not available");
                return;
            }
            DtbDebugProperties.getInstance();
            registerConfig(appId);
            long jCurrentTimeMillis = System.currentTimeMillis();
            long jLongValue = DtbSharedPreferences.getInstance().getSisLastCheckIn().longValue();
            if (DtbSharedPreferences.getInstance().getIsSisRegisterationSuccessful()) {
                long j = jCurrentTimeMillis - jLongValue;
                if (j <= 86400000) {
                    DtbLog.debug("SIS call not required, last registration duration:" + j + ", expiration:86400000");
                    return;
                }
            }
            new DtbAdvertisingInfo();
            boolean z = false;
            if (!com.amazon.aps.ads.privacy.c.f.c() && !DTBMetricsConfiguration.getInstance().isFeatureEnabled(DTBMetricsConfiguration.FEATURE_AIP_CALL_IF_NO_GDPR_CONSENT, false)) {
                com.amazon.aps.ads.c.a();
                return;
            }
            String sisEndpoint = DtbSharedPreferences.getInstance().getSisEndpoint();
            if (sisEndpoint.startsWith("null")) {
                DtbLog.debug("SIS is not ready");
                return;
            }
            StringBuilder sb = new StringBuilder(DtbDebugProperties.getSISUrl(sisEndpoint));
            if (jLongValue == 0) {
                DtbLog.info(LOG_TAG, "Trying to register ad id..");
                sb.append("/generate_did");
            } else {
                DtbLog.info(LOG_TAG, "Trying to update ad id..");
                sb.append("/update_dev_info");
                z = true;
            }
            HashMap<String, Object> mapBuildSISParams = buildSISParams(appId);
            JSONObject jSONObject2 = null;
            try {
                try {
                    jSONObject = new JSONObject();
                } catch (Throwable th) {
                    th = th;
                }
                try {
                    jSONObject.put("api", z ? "update_dev_info" : "generate_did");
                    DtbHttpClient dtbHttpClient = new DtbHttpClient(sb.toString());
                    dtbHttpClient.setUseSecure(DtbDebugProperties.getIsSecure(true));
                    dtbHttpClient.setParams(mapBuildSISParams);
                    dtbHttpClient.enableQueryParams();
                    DtbMetric dtbMetric4 = z ? DtbMetric.SIS_LATENCY_UPDATE_DEVICE_INFO : DtbMetric.SIS_LATENCY_REGISTER_EVENT;
                    this.metrics.startTimer(dtbMetric4);
                    dtbHttpClient.executePOST(60000);
                    this.metrics.stopTimer(dtbMetric4);
                    if (DtbCommonUtils.isNullOrEmpty(dtbHttpClient.getResponse())) {
                        DtbLog.debug("No response from sis call.");
                        throw new Exception("SIS Response is null");
                    }
                    JSONObject jSONObject3 = (JSONObject) new JSONTokener(dtbHttpClient.getResponse()).nextValue();
                    DtbSharedPreferences.getInstance().setIsSisRegisterationSuccessful(isRegistrationRequestSuccessful(jSONObject3));
                    if (DtbSharedPreferences.getInstance().getIsSisRegisterationSuccessful()) {
                        com.amazon.aps.shared.a.c(jSONObject, "sisApiSuccess", String.valueOf(DtbSharedPreferences.getInstance().isValidIdfaAvailable()));
                        if (dtbMetric4 != null) {
                            this.metrics.resetMetric(dtbMetric4);
                        }
                        pingSis(sisEndpoint, appId);
                        return;
                    }
                    DtbLog.info(LOG_TAG, "ad id failed registration: " + jSONObject3);
                    throw new Exception("ad id failed registration: ");
                } catch (JSONException e) {
                    e = e;
                    dtbMetric2 = null;
                    jSONObject2 = jSONObject;
                    DtbLog.error("JSON error parsing return from SIS: " + e.getMessage());
                    com.amazon.aps.shared.a.c(jSONObject2, "sisApiFailed", String.valueOf(DtbSharedPreferences.getInstance().isValidIdfaAvailable()));
                    if (dtbMetric2 != null) {
                        this.metrics.resetMetric(dtbMetric2);
                    }
                } catch (Exception e2) {
                    e = e2;
                    dtbMetric = null;
                    jSONObject2 = jSONObject;
                    DtbLog.error("Error registering device for ads:" + e);
                    com.amazon.aps.shared.a.c(jSONObject2, "sisApiFailed", String.valueOf(DtbSharedPreferences.getInstance().isValidIdfaAvailable()));
                    if (dtbMetric != null) {
                        this.metrics.resetMetric(dtbMetric);
                    }
                } catch (Throwable th2) {
                    th = th2;
                    dtbMetric3 = 0;
                    jSONObject2 = jSONObject;
                    com.amazon.aps.shared.a.c(jSONObject2, "sisApiFailed", String.valueOf(DtbSharedPreferences.getInstance().isValidIdfaAvailable()));
                    if (dtbMetric3 != 0) {
                        this.metrics.resetMetric(dtbMetric3);
                    }
                    throw th;
                }
            } catch (JSONException e3) {
                e = e3;
                dtbMetric2 = null;
            } catch (Exception e4) {
                e = e4;
                dtbMetric = null;
            } catch (Throwable th3) {
                th = th3;
                dtbMetric3 = 0;
            }
        }
    }

    private boolean isPingRequestSuccessful(JSONObject jSONObject) throws JSONException {
        if (!jSONObject.has("rcode")) {
            return false;
        }
        if (jSONObject.getInt("rcode") == 1) {
            DtbSharedPreferences.getInstance().saveSisLastPing(System.currentTimeMillis());
            DtbLog.info(LOG_TAG, "ad id is registered or updated successfully.");
            return true;
        }
        if (jSONObject.getInt("rcode") != 103 && (jSONObject.getInt("rcode") != 101 || !jSONObject.has("msg") || jSONObject.getInt("msg") != 103)) {
            return false;
        }
        DtbSharedPreferences.getInstance().saveSisLastPing(System.currentTimeMillis());
        DtbLog.info("gdpr consent not granted");
        return true;
    }

    private boolean isRegistrationRequestSuccessful(JSONObject jSONObject) throws JSONException {
        if (!jSONObject.has("rcode")) {
            return false;
        }
        DtbSharedPreferences.getInstance().saveSisLastCheckIn(System.currentTimeMillis());
        if (jSONObject.getInt("rcode") == 1 && jSONObject.has("adId")) {
            String string = jSONObject.getString("adId");
            if (jSONObject.has("idChanged") && jSONObject.getBoolean("idChanged")) {
                DtbLog.info(LOG_TAG, "ad id has changed, updating..");
                this.metrics.incrementMetric(DtbMetric.SIS_COUNTER_IDENTIFIED_DEVICE_CHANGED);
            }
            DtbSharedPreferences.getInstance().saveAdId(string);
            DtbLog.info(LOG_TAG, "ad id is registered or updated successfully.");
            return true;
        }
        if (jSONObject.getInt("rcode") != 103) {
            if (jSONObject.getInt("rcode") != 101 || !jSONObject.has("msg")) {
                return false;
            }
            if (jSONObject.optInt("msg") != 103 && !"need at least one native id in parameter".equals(jSONObject.get("msg"))) {
                return false;
            }
        }
        DtbSharedPreferences.getInstance().removeAdid();
        DtbLog.debug(LOG_TAG, "No ad-id returned");
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void lambda$verifyRegistration$0() {
        dtbDeviceRegistrationInstance.initializeAds();
        synchronized (com.amazon.aps.ads.d.class) {
            com.amazon.aps.ads.d.a = false;
        }
    }

    private void loadApsMetricsConfig() throws JSONException {
        String clientConfigVal = DTBMetricsConfiguration.getClientConfigVal(DTBMetricsConfiguration.APSMETRICS_LEVEL1_KEY, DTBMetricsConfiguration.APSMETRICS_LEVEL2_KEY, DTBMetricsConfiguration.APSMETRICS_URL, "https://prod.tahoe-analytics.publishers.advertising.a2z.com/logevent/putRecord");
        if (!AbstractC3550w.a(clientConfigVal)) {
            com.amazon.aps.shared.a.d = clientConfigVal;
        }
        double dDoubleValue = DTBMetricsConfiguration.getClientConfigVal(DTBMetricsConfiguration.APSMETRICS_LEVEL1_KEY, DTBMetricsConfiguration.APSMETRICS_LEVEL2_KEY, DTBMetricsConfiguration.APSMETRICS_SAMPLING_RATE, 0.1d).doubleValue();
        if (0.0d <= dDoubleValue && dDoubleValue <= 100.0d) {
            com.amazon.aps.shared.a.c = dDoubleValue;
            com.amazon.aps.shared.a.b();
        }
        String clientConfigVal2 = DTBMetricsConfiguration.getClientConfigVal(DTBMetricsConfiguration.APSMETRICS_LEVEL1_KEY, DTBMetricsConfiguration.APSMETRICS_LEVEL2_KEY, DTBMetricsConfiguration.APSMETRICS_APIKEY, "a5c71f6aff54eb34c826d952c285eaf0650b4259c83ae598962681a6429b63f6");
        if (AbstractC3550w.a(clientConfigVal2)) {
            return;
        }
        com.amazon.aps.shared.a.e = clientConfigVal2;
    }

    private boolean parseRegisterConfigResponse(String str, long j, boolean z) throws Exception {
        JSONObject jSONObject = (JSONObject) new JSONTokener(str).nextValue();
        if (jSONObject.has(CONFIG_PRIVACY_APPLICABLE)) {
            Object obj = jSONObject.get(CONFIG_PRIVACY_APPLICABLE);
            if (obj instanceof JSONArray) {
                com.amazon.aps.ads.privacy.c cVar = com.amazon.aps.ads.privacy.c.f;
                JSONArray jSONArray = (JSONArray) obj;
                if (jSONArray != null) {
                    cVar.getClass();
                    int length = jSONArray.length();
                    int i = 0;
                    while (true) {
                        if (i >= length) {
                            break;
                        }
                        int i2 = i + 1;
                        if ("gdprtcfv2".equals(jSONArray.get(i))) {
                            cVar.d = Boolean.TRUE;
                            break;
                        }
                        i = i2;
                    }
                } else {
                    cVar.d = Boolean.FALSE;
                }
            }
        }
        if (jSONObject.has("pj")) {
            DtbSharedPreferences.getInstance().savePJTemplate(jSONObject.getJSONObject("pj"));
        } else {
            DtbSharedPreferences.getInstance().removePJTemplate();
        }
        if (jSONObject.has(CONFIG_PRIVACY_KEY)) {
            setPrivacyConfigToSharedPreferences(jSONObject.getJSONArray(CONFIG_PRIVACY_KEY));
        } else {
            DtbSharedPreferences.getInstance().removePrivacyLocationConfig();
        }
        if (!jSONObject.has(DtbDebugProperties.AAX_HOSTNAME) && !jSONObject.has("sisURL") && !jSONObject.has(AAX_VIDEO_HOST_NAME_KEY)) {
            DtbLog.info(LOG_TAG, "ad configuration failed load: " + jSONObject);
            throw new Exception("ad configuration failed load");
        }
        if (jSONObject.has(DtbDebugProperties.AAX_HOSTNAME)) {
            DtbSharedPreferences.getInstance().saveAaxHostname(jSONObject.getString(DtbDebugProperties.AAX_HOSTNAME));
        }
        if (jSONObject.has("sisURL")) {
            z = DtbSharedPreferences.getInstance().saveSisEndpoint(jSONObject.getString("sisURL"));
        }
        if (jSONObject.has("ttl")) {
            DtbSharedPreferences.getInstance().saveConfigTtlInMilliSeconds(Long.parseLong(jSONObject.getString("ttl")));
        }
        if (jSONObject.has(AAX_VIDEO_HOST_NAME_KEY)) {
            DtbSharedPreferences.getInstance().saveAaxVideoHostname(jSONObject.getString(AAX_VIDEO_HOST_NAME_KEY));
        }
        if (jSONObject.has("bidTimeout")) {
            DtbSharedPreferences.getInstance().saveBidTimeout(Integer.valueOf(jSONObject.getInt("bidTimeout")));
        } else {
            DtbSharedPreferences.getInstance().removeBidTimeout();
        }
        DtbSharedPreferences.getInstance().saveConfigLastCheckIn(j);
        DtbLog.info(LOG_TAG, "ad configuration loaded successfully.");
        return z;
    }

    private void pingSis(String str, String str2) throws Exception {
        if (System.currentTimeMillis() - DtbSharedPreferences.getInstance().getSisLastPing() < 2592000000L) {
            return;
        }
        String adId = DtbSharedPreferences.getInstance().getAdId();
        if (adId == null || adId.isEmpty()) {
            DtbLog.info("error retrieving ad id, cancelling sis ping");
            return;
        }
        try {
            if (!DtbCommonUtils.isNetworkConnected()) {
                DtbLog.debug("Network is not available");
                return;
            }
            DtbHttpClient dtbHttpClient = new DtbHttpClient(str + "/ping");
            dtbHttpClient.setUseSecure(DtbDebugProperties.getIsSecure(true));
            HashMap<String, Object> map = new HashMap<>();
            map.put("appId", str2);
            map.put("adId", adId);
            Context context = AdRegistration.getContext();
            if (context != null) {
                SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
                Object obj = defaultSharedPreferences.contains("IABTCF_gdprApplies") ? defaultSharedPreferences.getAll().get("IABTCF_gdprApplies") : null;
                String string = defaultSharedPreferences.getString("IABTCF_TCString", null);
                if (obj != null) {
                    try {
                        if ((obj instanceof Integer) && (((Integer) obj).intValue() == 1 || ((Integer) obj).intValue() == 0)) {
                            map.put("gdpr", obj);
                        } else if (((obj instanceof String) && ((String) obj).equals("1")) || ((String) obj).equals("0")) {
                            map.put("gdpr", obj);
                        } else {
                            DtbLog.info("IABTCF_gdprApplies should be a 1 or 0 as per IAB guideline");
                        }
                    } catch (ClassCastException unused) {
                        DtbLog.info("IABTCF_gdprApplies should be a number as per IAB guideline");
                    }
                }
                if (string != null) {
                    map.put("gdpr_consent", string);
                }
                if (DTBMetricsConfiguration.getInstance().isFeatureEnabled(DTBMetricsConfiguration.FEATURE_FLAG_GPP_PARAMS_TO_AIP_CALL)) {
                    HashMap<String, Object> mapAddGPPParametersFromPreferences = DtbCommonUtils.addGPPParametersFromPreferences(defaultSharedPreferences);
                    if (!DtbCommonUtils.isNullOrEmpty(mapAddGPPParametersFromPreferences)) {
                        map.putAll(mapAddGPPParametersFromPreferences);
                    }
                }
            }
            String encodedNonIABString = AdRegistration.getEncodedNonIABString();
            if (!DtbCommonUtils.isNullOrEmpty(encodedNonIABString)) {
                map.put("gdpr_custom", encodedNonIABString);
            }
            dtbHttpClient.setParams(map);
            dtbHttpClient.executeGET(60000);
            if (DtbCommonUtils.isNullOrEmpty(dtbHttpClient.getResponse())) {
                DtbLog.debug("No response from sis ping.");
                throw new Exception("Ping SIS Response is null");
            }
            JSONObject jSONObject = (JSONObject) new JSONTokener(dtbHttpClient.getResponse()).nextValue();
            if (isPingRequestSuccessful(jSONObject)) {
                return;
            }
            DtbLog.info(LOG_TAG, "sis ping failed failed registration: " + jSONObject);
            throw new Exception("sis ping failed registration: ");
        } catch (Exception e) {
            DtbLog.error("Error pinging sis: " + e);
        }
    }

    /* JADX WARN: Can't wrap try/catch for region: R(12:20|(4:72|21|22|(1:24))|69|37|(1:42)(1:41)|(2:44|(1:48))|51|(1:55)|56|(1:60)|61|64) */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x0178, code lost:
    
        r12 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x01a2, code lost:
    
        com.amazon.device.ads.DtbLog.warn("Error when reading client config file for APSAndroidShared library" + r12);
     */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x015a A[Catch: RuntimeException -> 0x0178, TryCatch #0 {RuntimeException -> 0x0178, blocks: (B:37:0x0126, B:39:0x0152, B:44:0x015a, B:46:0x0167, B:48:0x0171, B:51:0x017a, B:53:0x0180, B:56:0x018c, B:58:0x0190, B:61:0x019c), top: B:69:0x0126 }] */
    /* JADX WARN: Removed duplicated region for block: B:55:0x018a  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x019a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean registerConfig(java.lang.String r12) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 446
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.amazon.device.ads.DtbDeviceRegistration.registerConfig(java.lang.String):boolean");
    }

    private void setPrivacyConfigToSharedPreferences(JSONArray jSONArray) throws JSONException {
        for (int i = 0; i < jSONArray.length(); i++) {
            try {
                JSONObject jSONObject = jSONArray.getJSONObject(i);
                if (jSONObject.has("location")) {
                    DtbSharedPreferences.getInstance().savePrivacyLocationConfig(jSONObject.getJSONObject("location"));
                    return;
                }
            } catch (RuntimeException e) {
                e = e;
                DtbLog.error(LOG_TAG, "Failed to parse privacy configuration");
                com.amazon.aps.shared.a.e(1, 1, "Failed to parse privacy configuration", e);
                return;
            } catch (JSONException e2) {
                e = e2;
                DtbLog.error(LOG_TAG, "Failed to parse privacy configuration");
                com.amazon.aps.shared.a.e(1, 1, "Failed to parse privacy configuration", e);
                return;
            }
        }
        DtbSharedPreferences.getInstance().removePrivacyLocationConfig();
    }

    public static synchronized void verifyRegistration() {
        boolean z;
        try {
            if (dtbDeviceRegistrationInstance == null) {
                dtbDeviceRegistrationInstance = new DtbDeviceRegistration();
                synchronized (com.amazon.aps.ads.d.class) {
                    com.amazon.aps.ads.d.a = false;
                }
            }
            synchronized (com.amazon.aps.ads.d.class) {
                z = com.amazon.aps.ads.d.a;
            }
            if (!z) {
                synchronized (com.amazon.aps.ads.d.class) {
                    com.amazon.aps.ads.d.a = true;
                }
                DtbThreadService.getInstance().execute(new RunnableC0131h(1));
            }
        } catch (Throwable th) {
            throw th;
        }
    }
}
