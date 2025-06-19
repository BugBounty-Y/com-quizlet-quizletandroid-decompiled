package com.amazon.device.ads;

import android.content.Context;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
class DtbDebugProperties {
    public static final String AAX_HOSTNAME = "aaxHostname";
    public static final String AAX_ROUTE53_ENABLED_CNAME = "route53EnabledAAXCname";
    public static final String CONFIG_HOSTNAME = "configHostname";
    public static final String CONFIG_REQUEST_HEADERS = "configRequestHeaders";
    public static final String INTERNAL_DEBUG_MODE = "internalDebugMode";
    private static final String LOG_TAG = "com.amazon.device.ads.DtbDebugProperties";
    public static final String SIS_URL = "sisUrl";
    private static final String TEST_OVERRIDE_FILE = "com.amazon.device.ads.dtb.debug.override";
    public static final String USE_SECURE = "useSecure";
    private static DtbDebugProperties debugProperties = null;
    static boolean isInternalDebugMode = false;
    private static Set<String> preDefinedKeys;
    private static HashMap<String, String> propertyMap = new HashMap<>();
    private static boolean isInitialized = false;

    public static String getAaxHostName(String str) {
        return getDebugProperty(AAX_HOSTNAME, str);
    }

    public static String getAaxVideoHostName(String str) {
        return getDebugProperty(AAX_ROUTE53_ENABLED_CNAME, str);
    }

    public static String getConfigHostName(String str) {
        return getDebugProperty(CONFIG_HOSTNAME, str);
    }

    public static HashMap<String, String> getConfigRequestHeaders(String str) throws JSONException {
        HashMap<String, String> map = new HashMap<>();
        try {
            JSONObject jSONObject = new JSONObject(getDebugProperty(CONFIG_REQUEST_HEADERS, str));
            Iterator<String> itKeys = jSONObject.keys();
            while (itKeys.hasNext()) {
                String next = itKeys.next();
                Object obj = jSONObject.get(next);
                if (obj instanceof String) {
                    map.put(next, String.valueOf(obj));
                }
            }
        } catch (RuntimeException | JSONException e) {
            com.amazon.aps.shared.a.e(2, 1, "Failed to execute getConfigRequestHeaders method", e);
        }
        return map;
    }

    public static HashMap<String, String> getDebugParams() {
        return (AdRegistration.isTestMode() && isInternalDebugMode) ? propertyMap : new HashMap<>();
    }

    private static String getDebugProperty(String str, String str2) {
        HashMap<String, String> map;
        return (!AdRegistration.isTestMode() || !isInternalDebugMode || (map = propertyMap) == null || map.get(str) == null) ? str2 : propertyMap.get(str);
    }

    public static String getEncodedUrlParams() {
        if (!isInternalDebugMode) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : propertyMap.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            try {
                if (!preDefinedKeys.contains(key.toLowerCase())) {
                    sb.append('&');
                    sb.append(key);
                    sb.append('=');
                    sb.append(URLEncoder.encode(value, "UTF-8"));
                }
            } catch (UnsupportedEncodingException e) {
                DtbLog.debugError(String.format("Cannot encode %d=%d due to exception %d", key, value, e.getMessage()));
            }
        }
        return sb.toString();
    }

    public static DtbDebugProperties getInstance() throws IOException {
        if (!isInitialized) {
            DtbLog.debug("Running the debug initialization.");
            debugProperties = new DtbDebugProperties();
            HashSet hashSet = new HashSet();
            preDefinedKeys = hashSet;
            hashSet.add(AAX_HOSTNAME.toLowerCase());
            preDefinedKeys.add(SIS_URL.toLowerCase());
            preDefinedKeys.add(USE_SECURE.toLowerCase());
            preDefinedKeys.add(CONFIG_HOSTNAME.toLowerCase());
            preDefinedKeys.add(INTERNAL_DEBUG_MODE.toLowerCase());
            preDefinedKeys.add(CONFIG_REQUEST_HEADERS.toLowerCase());
            initializeDtbDebugProperties();
        }
        return debugProperties;
    }

    public static boolean getIsSecure(boolean z) {
        String debugProperty = getDebugProperty(USE_SECURE, "");
        if (debugProperty.equals("true")) {
            return true;
        }
        if (debugProperty.equals("false")) {
            return false;
        }
        return z;
    }

    public static String getSISUrl(String str) {
        return getDebugProperty(SIS_URL, str);
    }

    public static void initializeDtbDebugProperties() throws IOException {
        try {
            Context context = AdRegistration.getContext();
            if (AdRegistration.isTestMode() && context == null) {
                DtbLog.debugError("unable to initialize debug preferences without setting app context");
                throw new IllegalArgumentException("unable to initialize debug preferences without setting app context");
            }
            String string = DtbCommonUtils.getApplicationBundle().getString(TEST_OVERRIDE_FILE);
            if (!DtbCommonUtils.isNullOrEmpty(string) && context != null) {
                DtbLog.debug("Override file: " + string);
                InputStream resourceAsStream = DtbCommonUtils.getResourceAsStream(string);
                if (resourceAsStream == null) {
                    DtbLog.debug("Failed to read override from classpath, trying to read override file from absolute location: " + string);
                    File file = new File(context.getFilesDir() + "/aps_override_properties/override.properties");
                    if (!file.exists()) {
                        DtbLog.debug("Couldn't find the override file, skipping.");
                        return;
                    }
                    resourceAsStream = new FileInputStream(file);
                }
                try {
                    DtbLog.debug("Reading debug params..");
                    Properties properties = new Properties();
                    properties.load(resourceAsStream);
                    for (Map.Entry entry : properties.entrySet()) {
                        String str = (String) entry.getKey();
                        if (DtbCommonUtils.isNullOrWhiteSpace(str)) {
                            DtbLog.debug("Error: The debug property name must not be null or empty string");
                        } else {
                            String strTrim = (String) entry.getValue();
                            if (strTrim != null) {
                                strTrim = strTrim.trim();
                            }
                            DtbLog.debug("Overrides found: " + str + " --> " + strTrim);
                            if (str.equalsIgnoreCase(INTERNAL_DEBUG_MODE)) {
                                isInternalDebugMode = strTrim.equalsIgnoreCase("true");
                            }
                            propertyMap.put(str, strTrim);
                        }
                    }
                    resourceAsStream.close();
                } catch (Throwable th) {
                    resourceAsStream.close();
                    throw th;
                }
            }
        } catch (Exception e) {
            DtbLog.debug("Error:: Failed to read the debug params. ignoring." + e.getStackTrace());
        }
        isInitialized = true;
    }

    public static void resetProperties() {
        isInitialized = false;
        propertyMap = new HashMap<>();
    }

    public boolean isDebugMode() {
        return isInternalDebugMode;
    }
}
