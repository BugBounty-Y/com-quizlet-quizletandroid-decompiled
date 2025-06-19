package com.amazon.device.ads;

import android.os.Build;
import android.telephony.TelephonyManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class SDKUtilities {
    static final String BID_HTML_TEMPLATE = "<div style=\"display:inline-block\"><div id=\"__dtbAd__\" style=\"overflow:hidden;\"><!--Placeholder for the Ad --></div><script type=\"text/javascript\">amzn.dtb.loadAd(\"%s\", \"%s\", \"%s\", %s, {isv: %s, dc: \"%s\", skipafter: %s, vtype: \"%s\"});</script></div>";
    private static final String LOG_TAG = "SDKUtilities";
    private static String amznDebugStateFlag = "false";

    public static class SimpleSize {
        int height;
        int width;

        public SimpleSize(int i, int i2) {
            this.width = i;
            this.height = i2;
        }

        public int getHeight() {
            return this.height;
        }

        public int getWidth() {
            return this.width;
        }

        public void setHeight(int i) {
            this.height = i;
        }

        public void setWidth(int i) {
            this.width = i;
        }
    }

    public static List<Object> convertJSONArrayToList(JSONArray jSONArray) throws JSONException {
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < jSONArray.length(); i++) {
            Object objConvertJSONObjectToMap = jSONArray.get(i);
            if (objConvertJSONObjectToMap instanceof JSONArray) {
                objConvertJSONObjectToMap = convertJSONArrayToList((JSONArray) objConvertJSONObjectToMap);
            } else if (objConvertJSONObjectToMap instanceof JSONObject) {
                objConvertJSONObjectToMap = convertJSONObjectToMap((JSONObject) objConvertJSONObjectToMap);
            }
            arrayList.add(objConvertJSONObjectToMap);
        }
        return arrayList;
    }

    public static Map<String, Object> convertJSONObjectToMap(JSONObject jSONObject) throws JSONException {
        HashMap map = new HashMap();
        Iterator<String> itKeys = jSONObject.keys();
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            Object obj = jSONObject.get(next);
            if (obj instanceof JSONObject) {
                map.put(next, convertJSONObjectToMap((JSONObject) obj));
            } else if (obj instanceof JSONArray) {
                map.put(next, convertJSONArrayToList((JSONArray) obj));
            } else {
                map.put(next, obj);
            }
        }
        return map;
    }

    public static String getBidInfo(DTBAdResponse dTBAdResponse) {
        Map<String, List<String>> defaultDisplayAdsRequestCustomParams;
        List<String> list;
        try {
            if (dTBAdResponse.getDTBAds().size() == 0) {
                return "";
            }
            if (dTBAdResponse.isVideo()) {
                defaultDisplayAdsRequestCustomParams = dTBAdResponse.getVideoAdsRequestCustomParamsAsList();
                list = defaultDisplayAdsRequestCustomParams.get(DTBAdLoader.A9_VID_KEY);
            } else {
                defaultDisplayAdsRequestCustomParams = dTBAdResponse.getDefaultDisplayAdsRequestCustomParams();
                list = defaultDisplayAdsRequestCustomParams.get(DTBAdLoader.A9_BID_ID_KEY);
            }
            String str = !DtbCommonUtils.isNullOrEmpty(list) ? list.get(0) : "";
            List<String> list2 = defaultDisplayAdsRequestCustomParams.get(DTBAdLoader.A9_HOST_KEY);
            String str2 = !DtbCommonUtils.isNullOrEmpty(list2) ? list2.get(0) : "";
            List<String> list3 = defaultDisplayAdsRequestCustomParams.get(DTBAdLoader.A9_PRICE_POINTS_KEY);
            String str3 = !DtbCommonUtils.isNullOrEmpty(list3) ? list3.get(0) : "";
            Map<String, List<String>> kvpDictionary = dTBAdResponse.getKvpDictionary();
            return String.format(DTBMetricsConfiguration.getClientConfigVal("creative", BID_HTML_TEMPLATE, "templates"), str3, str, str2, amznDebugStateFlag, Boolean.valueOf(dTBAdResponse.isVideo()), (!kvpDictionary.containsKey("dc") || kvpDictionary.get("dc").size() == 0) ? "" : kvpDictionary.get("dc").get(0), dTBAdResponse.getVideoSkipAfterDurationInSeconds(), !DtbCommonUtils.isNullOrEmpty(dTBAdResponse.getVideoInventoryType()) ? dTBAdResponse.getVideoInventoryType() : "");
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute getBidInfo method", e);
            return "";
        }
    }

    public static int getHeight(DTBAdResponse dTBAdResponse) {
        if (dTBAdResponse.getDTBAds().size() == 0) {
            return -1;
        }
        return dTBAdResponse.getDTBAds().get(0).getHeight();
    }

    public static String getPricePoint(DTBAdResponse dTBAdResponse) {
        try {
            List<String> list = (dTBAdResponse.isVideo() ? dTBAdResponse.getVideoAdsRequestCustomParamsAsList() : dTBAdResponse.getDefaultDisplayAdsRequestCustomParams()).get(DTBAdLoader.A9_PRICE_POINTS_KEY);
            return (list == null || list.size() <= 0) ? "" : list.get(0);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute getPricePoint method", e);
            return "";
        }
    }

    public static int getWidth(DTBAdResponse dTBAdResponse) {
        if (dTBAdResponse.getDTBAds().size() == 0) {
            return -1;
        }
        return dTBAdResponse.getDTBAds().get(0).getWidth();
    }

    @Deprecated
    public static boolean isEmulator() {
        try {
            String str = Build.FINGERPRINT;
            String str2 = Build.MODEL;
            String str3 = Build.MANUFACTURER;
            if (!str.startsWith("generic") && !str.startsWith(DtbDeviceDataRetriever.ORIENTATION_UNKNOWN) && !str2.contains("google_sdk") && !str2.contains("Emulator") && !str2.contains("Android SDK built for x86") && !str3.contains("Genymotion") && (!Build.BRAND.startsWith("generic") || !Build.DEVICE.startsWith("generic"))) {
                if (!"google_sdk".equals(Build.PRODUCT)) {
                    return false;
                }
            }
            return true;
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute isEmulator method", e);
            return false;
        }
    }

    public static boolean isTelSupported() {
        try {
            if (AdRegistration.getContext().checkSelfPermission("android.permission.CALL_PHONE") == 0) {
                if (((TelephonyManager) AdRegistration.getContext().getSystemService("phone")).getPhoneType() != 0) {
                    return true;
                }
            }
            return false;
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute isTelSupported method", e);
            return false;
        }
    }

    public static void setAmznDebugStateFlagValue(String str) {
        amznDebugStateFlag = str;
    }
}
