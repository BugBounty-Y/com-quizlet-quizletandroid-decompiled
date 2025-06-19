package com.amazon.device.ads;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class DTBMetricsConfiguration {
    static final String ANALYTICS_KEY_NAME = "analytics";
    static final String API_KEY_ANALYTICS_KEY_NAME = "api_key";
    public static final String APSMETRICS_APIKEY = "apiKey";
    public static final String APSMETRICS_LEVEL1_KEY = "apsmetricsv2";
    public static final String APSMETRICS_LEVEL2_KEY = "mobile";
    public static final String APSMETRICS_SAMPLING_RATE = "samplingPercentage";
    public static final String APSMETRICS_URL = "url";
    public static final String CONFIG_DIR = "config";
    public static final String CONFIG_WITH_JSON = "aps_mobile_client_config.json";
    static final String CREATIVE_TEMPLATES_KEY_NAME = "creative";
    public static final String CUSTOM_TAB_FEATURE_ENABLED_FLAG = "custom_tab_feature_enabled_flag";
    public static final boolean DEFAULT_AIP_CALL_IF_NO_GDPR_CONSENT = false;
    static final String DISTRIBUTION_PIXEL_SAMPLE_RATE_KEY_NAME = "distribution_pixel";
    public static final String FEATURE_AD_FORMAT_FROM_AAX = "ad_format_from_bid_response";
    public static final String FEATURE_AIP_CALL_IF_NO_GDPR_CONSENT = "aip_if_no_gdpr_consent";
    public static final String FEATURE_APSMETRICS_EXTENDED_METRICS = "apsmetrics_extended_metrics";
    static final String FEATURE_CLEAR_AAX_HOST_NAME_FROM_SHARED_PREF = "clear_aaxHostName";
    public static final String FEATURE_CONFIG_IN_INIT = "config_in_init";
    public static final String FEATURE_ENABLE_APS_BID_FLAG = "enable_aps_bid_flag";
    public static final String FEATURE_ENABLE_DEFAULT_AD_SIZE = "enable_default_ad_size_to_bid_request";
    static final String FEATURE_FLAG = "feature_toggle";
    public static final String FEATURE_FLAG_GPP_PARAMS_TO_AIP_CALL = "enable_gpp_params_to_aip_call";
    private static final String LOG_TAG = "DTBMetricsConfiguration";
    static final String OM_SDK_CONFIGURABLE_PARTNER_KEY_NAME = "partner_name";
    static final String OM_SDK_DENIED_VERSION_KEY_NAME = "denied_version_list";
    static final String OM_SDK_FEATURE_ENABLE_KEY_NAME = "feature_enabled";
    static final String OM_SDK_FEATURE_KEY_NAME = "om_sdk_feature";
    static final String SAMPLE_RATES_KEY_NAME = "sample_rates";
    static final String SAMPLING_RATE_ANALYTICS_KEY_NAME = "sampling_rate";
    static final String SPP_FLAG_DEFAULT_VALUE = "leq";
    static final String SPP_FLAG_KEY_NAME = "spp_flag";
    static final String TEMPLATES_KEY_NAME = "templates";
    static final String URL_ANALYTICS_KEY_NAME = "url";
    static final String WRAPPING_PIXEL_SAMPLE_RATE_KEY_NAME = "wrapping_pixel";
    private static DTBMetricsConfiguration theInstance;
    private JSONObject configuration = new JSONObject();
    static final Integer WRAPPING_PIXEL_DEFAULT_VALUE = -1;
    static final Integer DISTRIBUTION_PIXEL_DEFAULT_VALUE = 1;
    static final Integer ANALYTIC_PIXEL_DEFAULT_VALUE = 1;
    private static int configSeq = 0;

    private DTBMetricsConfiguration() {
        loadMobileClientConfig();
    }

    public static Integer getAnalyticsParams(String str, int i) {
        try {
            JSONObject configParams = getInstance().getConfigParams(ANALYTICS_KEY_NAME);
            if (configParams != null) {
                try {
                    if (configParams.has(str)) {
                        return Integer.valueOf(configParams.getInt(str));
                    }
                } catch (Exception unused) {
                    DtbLog.warn("Unable to get sample rates for " + str + " from configuration. Using default value");
                }
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute getSampleRateForPixel method", e);
        }
        return Integer.valueOf(i);
    }

    public static Double getClientConfigVal(String str, String str2, String str3, double d) throws JSONException {
        try {
            JSONObject jSONObject = getInstance().getConfigParams(str).getJSONObject(str2);
            if (jSONObject != null && jSONObject.has(str3)) {
                return Double.valueOf(jSONObject.getDouble(str3));
            }
        } catch (RuntimeException | JSONException e) {
            e.toString();
            com.amazon.aps.ads.c.a();
        }
        return Double.valueOf(d);
    }

    private JSONObject getConfigParams(String str) {
        if (!this.configuration.has(str)) {
            return null;
        }
        try {
            return this.configuration.getJSONObject(str);
        } catch (JSONException unused) {
            DtbLog.error("Unable to get" + str + "from configuration");
            return null;
        }
    }

    public static List<String> getDeniedOmSdkVersionList(String str) {
        ArrayList arrayList = new ArrayList();
        try {
            JSONObject configParams = getInstance().getConfigParams(OM_SDK_FEATURE_KEY_NAME);
            if (configParams != null) {
                try {
                    if (configParams.has(str)) {
                        JSONArray jSONArray = configParams.getJSONArray(str);
                        for (int i = 0; i < jSONArray.length(); i++) {
                            Object obj = jSONArray.get(i);
                            if (obj instanceof String) {
                                arrayList.add(obj.toString());
                            }
                        }
                    }
                } catch (JSONException e) {
                    com.amazon.aps.shared.a.e(1, 1, "Fail to execute getOMSDKVersionList method", e);
                }
            }
        } catch (RuntimeException e2) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute getOMSDKVersionList method", e2);
        }
        return arrayList;
    }

    public static synchronized DTBMetricsConfiguration getInstance() {
        try {
            if (theInstance == null) {
                theInstance = new DTBMetricsConfiguration();
            }
        } catch (Throwable th) {
            throw th;
        }
        return theInstance;
    }

    private String getWorkingDirContent() throws IOException {
        return DTBAdUtil.loadFile(CONFIG_WITH_JSON, CONFIG_DIR);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: loadConfigurationFromWeb, reason: merged with bridge method [inline-methods] */
    public void lambda$loadMobileClientConfig$0() {
        try {
            DtbHttpClient dtbHttpClient = new DtbHttpClient(WebResourceOptions.getCDNHost(CONFIG_WITH_JSON) + CONFIG_WITH_JSON);
            dtbHttpClient.setUseSecure(DtbDebugProperties.getIsSecure(true));
            dtbHttpClient.executeGET(60000);
            if (dtbHttpClient.getResponseCode() != 200) {
                throw new RuntimeException("resource aps_mobile_client_config.json not available");
            }
            String response = dtbHttpClient.getResponse();
            if (com.amazon.aps.ads.privacy.c.f.c()) {
                File filesDir = AdRegistration.getContext().getFilesDir();
                File fileCreateTempFile = createTempFile(filesDir);
                storeTempFile(fileCreateTempFile, response);
                File file = new File(filesDir.getAbsolutePath() + "/config/aps_mobile_client_config.json");
                if (file.exists()) {
                    file.delete();
                }
                if (!fileCreateTempFile.renameTo(file)) {
                    DtbLog.error("Rename failed");
                }
            }
            loadConfiguration(response);
        } catch (Exception e) {
            com.amazon.aps.shared.a.e(1, 1, "Error loading the configuration from web", e);
        }
    }

    public File createTempFile(File file) {
        try {
            return File.createTempFile("temp", "json", file);
        } catch (Exception unused) {
            com.amazon.aps.ads.c.b(LOG_TAG, "Error creating the temporary file");
            return null;
        }
    }

    public String getConfigVal(String str) {
        if (!this.configuration.has(str)) {
            return null;
        }
        try {
            return this.configuration.getString(str);
        } catch (JSONException unused) {
            DtbLog.error("Unable to get" + str + "from configuration");
            return null;
        }
    }

    public boolean isFeatureEnabled(String str, boolean z) throws JSONException {
        JSONObject jSONObject = this.configuration;
        if (jSONObject != null && jSONObject.has(FEATURE_FLAG)) {
            try {
                JSONObject jSONObject2 = this.configuration.getJSONObject(FEATURE_FLAG);
                if (jSONObject2.has(str)) {
                    return jSONObject2.getBoolean(str);
                }
            } catch (JSONException unused) {
                DtbLog.error("Unable to get feature flag from configuration");
            }
        }
        return z;
    }

    public synchronized boolean isTypeEnabled(String str) {
        JSONObject jSONObject = this.configuration;
        if (jSONObject != null) {
            try {
                JSONObject jSONObject2 = jSONObject.getJSONObject("metrics");
                if (jSONObject2.has(str)) {
                    return jSONObject2.getBoolean(str);
                }
            } catch (JSONException unused) {
                DtbLog.error("Unable to get metrics from configuration");
            }
        }
        return false;
    }

    public void loadConfiguration() {
        loadConfiguration(null);
    }

    public void loadMobileClientConfig() {
        if (com.amazon.aps.ads.privacy.c.f.c()) {
            DTBAdUtil.createDirIfDoesNotExist(CONFIG_DIR);
        }
        loadConfiguration();
        DtbThreadService.getInstance().execute(new l(this, 2));
    }

    public boolean storeTempFile(File file, String str) throws IOException {
        try {
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write(str);
            fileWriter.close();
            return true;
        } catch (Exception unused) {
            com.amazon.aps.ads.c.b(LOG_TAG, "Error creating the temporary file");
            return false;
        }
    }

    public synchronized void loadConfiguration(String str) {
        try {
            configSeq++;
            if (str == null) {
                try {
                    if (com.amazon.aps.ads.privacy.c.f.c()) {
                        str = getWorkingDirContent();
                    }
                } catch (IOException e) {
                    e = e;
                    com.amazon.aps.shared.a.e(1, 1, "Error loading the configuration from assets", e);
                    com.amazon.aps.shared.a.c(null, "remoteJsonFetchFailed", String.valueOf(configSeq));
                } catch (RuntimeException e2) {
                    e = e2;
                    com.amazon.aps.shared.a.e(1, 1, "Error loading the configuration from assets", e);
                    com.amazon.aps.shared.a.c(null, "remoteJsonFetchFailed", String.valueOf(configSeq));
                } catch (JSONException e3) {
                    e = e3;
                    com.amazon.aps.shared.a.e(1, 1, "Error loading the configuration from assets", e);
                    com.amazon.aps.shared.a.c(null, "remoteJsonFetchFailed", String.valueOf(configSeq));
                }
            }
            if (str == null) {
                str = DTBAdUtil.loadFromAssets(CONFIG_WITH_JSON);
            }
            if (str != null) {
                this.configuration = new JSONObject(str);
            }
            com.amazon.aps.shared.a.c(null, "remoteJsonFetchSuccess", String.valueOf(configSeq));
        } catch (Throwable th) {
            throw th;
        }
    }

    public boolean isFeatureEnabled(String str) {
        return isFeatureEnabled(str, true);
    }

    public static String getClientConfigVal(String str, String str2, String str3, String str4) throws JSONException {
        try {
            JSONObject jSONObject = getInstance().getConfigParams(str).getJSONObject(str2);
            if (jSONObject != null && jSONObject.has(str3)) {
                return jSONObject.getString(str3);
            }
        } catch (RuntimeException | JSONException e) {
            e.toString();
            com.amazon.aps.ads.c.a();
        }
        return str4;
    }

    public static Integer getClientConfigVal(String str, int i, String str2) {
        try {
            JSONObject configParams = getInstance().getConfigParams(str2);
            if (configParams != null) {
                try {
                    if (configParams.has(str)) {
                        return Integer.valueOf(configParams.getInt(str));
                    }
                } catch (Exception unused) {
                    DtbLog.warn("Unable to get" + str2 + "for " + str + " from configuration. Using default value");
                }
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute getClientConfigVal method", e);
        }
        return Integer.valueOf(i);
    }

    public static String getClientConfigVal(String str, String str2, String str3) {
        try {
            JSONObject configParams = getInstance().getConfigParams(str3);
            if (configParams != null) {
                try {
                    if (configParams.has(str)) {
                        return configParams.getString(str);
                    }
                } catch (Exception unused) {
                    DtbLog.warn("Unable to get" + str3 + "for " + str + " from configuration. Using default value");
                }
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute getClientConfigVal method", e);
        }
        return str2;
    }

    public static String getClientConfigVal(String str, String str2) {
        String configVal;
        try {
            configVal = getInstance().getConfigVal(str2);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute getClientConfigVal method", e);
        }
        return !DtbCommonUtils.isNullOrEmpty(configVal) ? configVal : str;
    }
}
