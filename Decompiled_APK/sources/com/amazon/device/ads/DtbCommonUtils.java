package com.amazon.device.ads;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.os.Looper;
import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class DtbCommonUtils {
    private static final String IAB_GPP_SID = "gpp_sid";
    private static final String IAB_GPP_STRING = "gpp";

    public static class APIVersion {
        public int majorVersion = 0;
        public int minorVersion = 0;
    }

    private DtbCommonUtils() {
    }

    public static HashMap<String, Object> addGPPParametersFromPreferences(SharedPreferences sharedPreferences) {
        HashMap<String, Object> map = new HashMap<>();
        try {
            Object obj = sharedPreferences.contains(OTGppKeys.IAB_GPP_HDR_GPP_STRING) ? sharedPreferences.getAll().get(OTGppKeys.IAB_GPP_HDR_GPP_STRING) : null;
            if ((obj instanceof String) && !isNullOrEmpty((String) obj)) {
                map.put(IAB_GPP_STRING, (String) obj);
            }
            Object obj2 = sharedPreferences.contains(OTGppKeys.IAB_GPP_GPP_SID) ? sharedPreferences.getAll().get(OTGppKeys.IAB_GPP_GPP_SID) : null;
            if ((obj2 instanceof String) && !isNullOrEmpty((String) obj2)) {
                JSONArray jSONArray = new JSONArray();
                Matcher matcher = Pattern.compile("\\d+").matcher((String) obj2);
                while (matcher.find()) {
                    for (int i = 0; i <= matcher.groupCount(); i++) {
                        jSONArray.put(Integer.parseInt(matcher.group(i)));
                    }
                }
                if (jSONArray.length() > 0) {
                    map.put(IAB_GPP_SID, jSONArray);
                    return map;
                }
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to get Global privacy platform params from shared preference", e);
        }
        return map;
    }

    public static DTBAdRequest createAutoRefreshAdLoader(DTBAdRequest dTBAdRequest) {
        DTBAdRequest dTBAdRequest2 = new DTBAdRequest(dTBAdRequest.getAdNetworkInfo());
        if (!isNullOrEmpty(dTBAdRequest.getAdSizes())) {
            dTBAdRequest2.setAdSizes(dTBAdRequest.getAdSizes());
        }
        if (!isNullOrEmpty(dTBAdRequest.getSlotGroupName())) {
            dTBAdRequest2.setSlotGroup(dTBAdRequest.getSlotGroupName());
        }
        if (!isNullOrEmpty(dTBAdRequest.getCustomTargets())) {
            dTBAdRequest2.setCustomTargets(dTBAdRequest.getCustomTargets());
        }
        dTBAdRequest2.setRefreshFlag(true);
        return dTBAdRequest2;
    }

    public static String exceptionToString(Exception exc) {
        String localizedMessage = exc.getLocalizedMessage();
        return localizedMessage != null ? android.support.v4.media.session.a.B("(", localizedMessage, ")") : "";
    }

    @NonNull
    public static APIVersion getAPIVersion(String str) {
        APIVersion aPIVersion = new APIVersion();
        if (str != null) {
            StringTokenizer stringTokenizer = new StringTokenizer(str, ".");
            String strNextToken = stringTokenizer.hasMoreTokens() ? stringTokenizer.nextToken() : str;
            String strNextToken2 = stringTokenizer.hasMoreTokens() ? stringTokenizer.nextToken() : "0";
            try {
                aPIVersion.majorVersion = Integer.parseInt(strNextToken);
                aPIVersion.minorVersion = Integer.parseInt(strNextToken2);
                return aPIVersion;
            } catch (NumberFormatException unused) {
                DtbLog.warn("Invalid API version:".concat(str));
            }
        }
        return aPIVersion;
    }

    public static Bundle getApplicationBundle() throws PackageManager.NameNotFoundException {
        if (AdRegistration.getContext() != null) {
            return AdRegistration.getContext().getPackageManager().getApplicationInfo(AdRegistration.getContext().getPackageName(), 128).metaData;
        }
        throw new IllegalStateException("Application Context can't be null");
    }

    public static String getHostNameFromUrl(String str) {
        if (!str.startsWith(DtbConstants.HTTPS) && !str.startsWith("http://")) {
            str = DtbConstants.HTTPS.concat(str);
        }
        try {
            return new URI(str).getHost();
        } catch (Exception unused) {
            DtbLog.error(String.format("The url %s that is passed for parsing is invalid. Please check the URL", new Object[0]));
            return null;
        }
    }

    public static Integer getIntegerFieldValue(String str, String str2) {
        try {
            Field declaredField = Class.forName(str).getDeclaredField(str2);
            declaredField.setAccessible(true);
            if (declaredField.isAccessible()) {
                return (Integer) declaredField.get(null);
            }
            DtbLog.debug("Field:" + str2 + " is not accessable");
            return null;
        } catch (ClassNotFoundException unused) {
            DtbLog.debug("Class notFound:" + str);
            return null;
        } catch (IllegalAccessException e) {
            DtbLog.debug("Illegal Access exception:" + e.getMessage());
            return null;
        } catch (IllegalArgumentException e2) {
            DtbLog.debug("Illegal Argument exception:" + e2.getMessage());
            return null;
        } catch (NoSuchFieldException unused2) {
            DtbLog.debug("Field:" + str2 + " does not exist");
            return null;
        } catch (SecurityException unused3) {
            DtbLog.debug("Field:" + str2 + " is not accessable");
            return null;
        }
    }

    public static long getMilliSeconds(String str) {
        return Long.parseLong(str) * 1000;
    }

    public static JSONObject getParamsAsJson(Map<String, Object> map) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        for (String str : map.keySet()) {
            jSONObject.put(str, map.get(str));
        }
        return jSONObject;
    }

    public static String getParamsAsJsonString(Map<String, Object> map) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        for (String str : map.keySet()) {
            jSONObject.put(str, map.get(str));
        }
        return jSONObject.toString();
    }

    public static InputStream getResourceAsStream(String str) {
        return DtbCommonUtils.class.getResourceAsStream(str);
    }

    public static String getSDKFramework() {
        try {
            Class.forName("com.unity3d.player.UnityPlayerActivity");
            return "unity";
        } catch (ClassNotFoundException unused) {
            return com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE;
        }
    }

    public static String getSDKMRAIDVersion() {
        return getSDKVersion();
    }

    public static String getSDKVersion() {
        return "aps-android-10.1.1";
    }

    public static String getStringFieldValue(String str, String str2) throws NoSuchFieldException, SecurityException {
        try {
            Field declaredField = Class.forName(str).getDeclaredField(str2);
            declaredField.setAccessible(true);
            if (declaredField.isAccessible()) {
                return (String) declaredField.get(null);
            }
            DtbLog.debug("Field:" + str2 + " is not accessable");
            return null;
        } catch (ClassNotFoundException unused) {
            DtbLog.debug("Class not found:" + str);
            return null;
        } catch (IllegalAccessException e) {
            DtbLog.debug("Illegal Access exception:" + e.getMessage());
            return null;
        } catch (IllegalArgumentException e2) {
            DtbLog.debug("Illegal Argument exception:" + e2.getMessage());
            return null;
        } catch (NoSuchFieldException unused2) {
            DtbLog.debug("Field:" + str2 + " does not exist");
            return null;
        } catch (SecurityException unused3) {
            DtbLog.debug("Field:" + str2 + " is not accessable");
            return null;
        }
    }

    public static String getURLEncodedString(String str) {
        if (isNullOrEmpty(str)) {
            return str;
        }
        try {
            return URLEncoder.encode(str, "UTF-8").replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
        } catch (UnsupportedEncodingException unused) {
            DtbLog.debugError("Unable to url encode :" + str);
            return str;
        }
    }

    public static Bundle initializeEmptyBundle() {
        return new Bundle();
    }

    @TargetApi(17)
    public static boolean isActivityDestroyed(Activity activity) {
        return activity.isDestroyed();
    }

    public static boolean isClassAvailable(String str) throws ClassNotFoundException {
        try {
            Class.forName(str);
            return true;
        } catch (ClassNotFoundException unused) {
            return false;
        }
    }

    public static boolean isNetworkConnected() {
        Network activeNetwork;
        if (AdRegistration.getContext() != null && AdRegistration.getContext().checkCallingOrSelfPermission("android.permission.ACCESS_NETWORK_STATE") == 0) {
            ConnectivityManager connectivityManager = (ConnectivityManager) AdRegistration.getContext().getSystemService("connectivity");
            if (connectivityManager != null && (activeNetwork = connectivityManager.getActiveNetwork()) != null) {
                try {
                    NetworkCapabilities networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork);
                    if (networkCapabilities != null) {
                        if (!networkCapabilities.hasTransport(0)) {
                            if (networkCapabilities.hasTransport(1)) {
                            }
                        }
                    }
                } catch (RuntimeException e) {
                    com.amazon.aps.shared.a.e(1, 1, "failed to get network capabilities in DtbCommonUtils.isNetworkConnected", e);
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    public static boolean isNullOrEmpty(String str) {
        return str == null || str.equals("");
    }

    public static boolean isNullOrWhiteSpace(String str) {
        return isNullOrEmpty(str) || str.trim().equals("");
    }

    public static boolean isOnMainThread() {
        return Looper.getMainLooper().getThread() == Thread.currentThread();
    }

    public static int parseInt(String str, int i) {
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException unused) {
            DtbLog.debugError("Exception parsing the integer from string:" + str);
            return i;
        }
    }

    public static boolean isNullOrEmpty(Map map) {
        return map == null || map.isEmpty();
    }

    public static boolean isNullOrEmpty(JSONObject jSONObject) {
        return jSONObject == null || jSONObject.length() == 0;
    }

    public static boolean isNullOrEmpty(List list) {
        return list == null || list.size() == 0;
    }
}
