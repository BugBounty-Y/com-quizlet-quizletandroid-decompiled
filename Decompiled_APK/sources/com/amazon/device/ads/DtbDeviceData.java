package com.amazon.device.ads;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.webkit.WebSettings;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class DtbDeviceData {
    private static final String DEFAULT_USER_AGENT = "Android";
    static final String DEVICE_DATA_CARRIER_KEY = "carrier";
    static final String DEVICE_DATA_CONNECTION_TYPE_KEY = "connectionType";
    static final String DEVICE_DATA_COUNTRY_KEY = "country";
    static final String DEVICE_DATA_HWV_KEY = "hwv";
    static final String DEVICE_DATA_LANGUAGE_KEY = "language";
    static final String DEVICE_DATA_MAKE_KEY = "make";
    public static final String DEVICE_DATA_MODEL_KEY = "model";
    public static final String DEVICE_DATA_ORIENTATION_KEY = "orientation";
    static final String DEVICE_DATA_OS_KEY = "os";
    public static final String DEVICE_DATA_OS_VERSION_KEY = "osVersion";
    static final String DEVICE_DATA_PPI_KEY = "ppi";
    static final String DEVICE_DATA_SCALING_FACTOR_KEY = "scalingFactor";
    public static final String DEVICE_DATA_SCREEN_SIZE_KEY = "screenSize";
    private static final String LOG_TAG = "DtbDeviceData";
    private static DtbDeviceData deviceDataInstance;
    private boolean bad_serial = false;
    private boolean bad_udid = false;
    private boolean bad_mac = false;
    private String sha1_mac = null;
    private String sha1_udid = null;
    private String sha1_serial = null;
    private String ua = null;
    private String screenSize = null;
    private String orientation = null;
    private HashMap<String, Object> deviceParams = new HashMap<>();
    private JSONObject deviceInfoJson = new JSONObject();

    private DtbDeviceData(Context context) {
        getOrientation();
        getScreenSize();
        getDeviceInfoJson();
        getUserAgent();
        buildDeviceParams();
    }

    private void buildDeviceParams() {
        this.deviceParams.put("dt", DtbConstants.NATIVE_OS_NAME);
        this.deviceParams.put("app", "app");
        this.deviceParams.put("aud", "3p");
        String str = this.ua;
        if (str != null) {
            this.deviceParams.put("ua", str);
        }
        this.deviceParams.put("sdkVer", DtbCommonUtils.getSDKVersion());
        JSONObject jSONObject = this.deviceInfoJson;
        if (jSONObject != null) {
            this.deviceParams.put("dinfo", jSONObject);
        }
    }

    private String generateSha1Hash(String str) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        messageDigest.update(str.getBytes());
        byte[] bArrDigest = messageDigest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : bArrDigest) {
            sb.append(Integer.toHexString((b & 255) | 256).substring(1));
        }
        return sb.toString();
    }

    public static String getConnectionType() {
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) AdRegistration.getContext().getSystemService("connectivity")).getActiveNetworkInfo();
        if (activeNetworkInfo == null || !activeNetworkInfo.isConnected()) {
            return "0";
        }
        int type = activeNetworkInfo.getType();
        return type != 0 ? type != 1 ? type != 6 ? "0" : "13" : "Wifi" : Integer.toString(activeNetworkInfo.getSubtype());
    }

    public static DtbDeviceData getDeviceDataInstance() {
        if (AdRegistration.getContext() == null) {
            DtbLog.debugError("unable to initialize advertising info without setting app context");
            throw new IllegalArgumentException("unable to initialize advertising info without setting app context");
        }
        if (deviceDataInstance == null) {
            if (AdRegistration.getContext() == null) {
                DtbLog.debugError("Invalid intialization of Device Data. Context is null");
                throw new IllegalArgumentException("Invalid intialization of Device Data. Context is null");
            }
            deviceDataInstance = new DtbDeviceData(AdRegistration.getContext());
        }
        return deviceDataInstance;
    }

    private void getDeviceInfoJson() {
        String str = Build.MODEL;
        String str2 = Build.MANUFACTURER;
        String str3 = Build.VERSION.RELEASE;
        String str4 = Build.DEVICE;
        String country = Locale.getDefault().getCountry();
        String language = Locale.getDefault().getLanguage();
        String connectionType = getConnectionType();
        int screenPpi = getScreenPpi();
        TelephonyManager telephonyManager = (TelephonyManager) AdRegistration.getContext().getSystemService("phone");
        String networkOperatorName = telephonyManager != null ? telephonyManager.getNetworkOperatorName() : null;
        String string = Float.toString((str2.equals("motorola") && str.equals("MB502")) ? 1.0f : getDisplayMetrics().scaledDensity);
        try {
            placeProperty(DEFAULT_USER_AGENT, DEVICE_DATA_OS_KEY);
            placeProperty(str, DEVICE_DATA_MODEL_KEY);
            placeProperty(str2, DEVICE_DATA_MAKE_KEY);
            placeProperty(str4, DEVICE_DATA_HWV_KEY);
            placeProperty(str3, DEVICE_DATA_OS_VERSION_KEY);
            placeProperty(country, "country");
            placeProperty(networkOperatorName, DEVICE_DATA_CARRIER_KEY);
            placeProperty(language, DEVICE_DATA_LANGUAGE_KEY);
            placeProperty(this.screenSize, DEVICE_DATA_SCREEN_SIZE_KEY);
            placeProperty(string, DEVICE_DATA_SCALING_FACTOR_KEY);
            placeProperty(Integer.toString(screenPpi), DEVICE_DATA_PPI_KEY);
            placeProperty(this.orientation, DEVICE_DATA_ORIENTATION_KEY);
            placeProperty(connectionType, DEVICE_DATA_CONNECTION_TYPE_KEY);
        } catch (UnsupportedEncodingException unused) {
            DtbLog.error(LOG_TAG, "Unsupported encoding");
        } catch (JSONException unused2) {
            DtbLog.error(LOG_TAG, "JSONException while producing deviceInfoJson");
        }
    }

    private DisplayMetrics getDisplayMetrics() {
        return AdRegistration.getContext().getResources().getDisplayMetrics();
    }

    private void getOrientation() {
        this.orientation = DtbDeviceDataRetriever.getOrientation(AdRegistration.getContext());
    }

    private int getScreenPpi() {
        DisplayMetrics displayMetrics = getDisplayMetrics();
        return (int) (Math.sqrt(Math.pow(displayMetrics.heightPixels, 2.0d) + Math.pow(displayMetrics.widthPixels, 2.0d)) / Math.sqrt(Math.pow(displayMetrics.heightPixels / displayMetrics.ydpi, 2.0d) + Math.pow(displayMetrics.widthPixels / displayMetrics.xdpi, 2.0d)));
    }

    private void getScreenSize() {
        this.screenSize = DtbDeviceDataRetriever.getScreenSize(new DisplayMetrics(), this.orientation);
    }

    private void getUserAgent() {
        try {
            this.ua = WebSettings.getDefaultUserAgent(AdRegistration.getContext());
        } catch (Exception unused) {
            DtbLog.info("Unable to Get User Agent, Setting it to default");
            this.ua = DEFAULT_USER_AGENT;
        }
    }

    public HashMap<String, Object> getDeviceParams() {
        if (!this.deviceParams.containsKey("ua") || (this.deviceParams.containsKey("ua") && this.deviceParams.get("ua").equals(DEFAULT_USER_AGENT))) {
            getUserAgent();
            buildDeviceParams();
        }
        return this.deviceParams;
    }

    public JSONObject getParamsJson() {
        try {
            getOrientation();
            placeProperty(this.orientation, DEVICE_DATA_ORIENTATION_KEY);
            getScreenSize();
            placeProperty(this.screenSize, DEVICE_DATA_SCREEN_SIZE_KEY);
        } catch (Exception e) {
            DtbLog.error("Error:" + e);
        }
        return this.deviceInfoJson;
    }

    public JSONObject getParamsJsonGetSafe() {
        JSONObject jSONObject = new JSONObject();
        Iterator<String> itKeys = this.deviceInfoJson.keys();
        while (itKeys.hasNext()) {
            try {
                String next = itKeys.next();
                Object obj = this.deviceInfoJson.get(next);
                if (obj instanceof String) {
                    jSONObject.put(next, URLEncoder.encode((String) obj, "UTF-8"));
                }
            } catch (Exception unused) {
                DtbLog.error("Error converting to JsonGetSafe");
            }
        }
        return jSONObject;
    }

    public String getUserAgentString() {
        return this.ua;
    }

    public void placeProperty(String str, String str2) throws JSONException, UnsupportedEncodingException {
        if (str == null || str.isEmpty()) {
            return;
        }
        this.deviceInfoJson.put(str2, str);
    }
}
