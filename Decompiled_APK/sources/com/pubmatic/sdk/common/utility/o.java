package com.pubmatic.sdk.common.utility;

import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Rect;
import android.location.Location;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.pubmatic.sdk.common.log.POBLog;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class o {
    @NonNull
    public static String buildUriWithQueryParams(@NonNull Uri uri, @NonNull Map<String, String> map) {
        Uri.Builder builderBuildUpon = uri.buildUpon();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            builderBuildUpon.appendQueryParameter(entry.getKey(), entry.getValue());
        }
        return builderBuildUpon.build().toString();
    }

    @NonNull
    public static String buildUrlWithQueryParam(@NonNull String str, @NonNull String str2, @NonNull String str3) {
        Uri.Builder builderBuildUpon = Uri.parse(str).buildUpon();
        builderBuildUpon.appendQueryParameter(str2, str3);
        return builderBuildUpon.build().toString();
    }

    public static int convertDpToPixel(int i) {
        return (int) (i * Resources.getSystem().getDisplayMetrics().density);
    }

    public static float convertDpToPixelWithFloatPrecession(int i) {
        return i * Resources.getSystem().getDisplayMetrics().density;
    }

    public static int convertPixelToDp(int i) {
        return (int) (i / Resources.getSystem().getDisplayMetrics().density);
    }

    public static List<String> convertStringJsonArrayToList(JSONArray jSONArray) {
        if (isJsonArrayNullOrEmpty(jSONArray)) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < jSONArray.length(); i++) {
            if (!jSONArray.isNull(i)) {
                arrayList.add(jSONArray.optString(i));
            }
        }
        return arrayList;
    }

    public static double convertToSeconds(String str, String str2) throws NumberFormatException {
        if (str2 == null || str2.isEmpty()) {
            return 0.0d;
        }
        if (!str2.contains("%")) {
            return getSeconds(str2);
        }
        try {
            return (getSeconds(str) * Double.parseDouble(str2.replace("%", ""))) / 100.0d;
        } catch (NumberFormatException unused) {
            POBLog.error("POBUtils", "Invalid time value", new Object[0]);
            return 0.0d;
        }
    }

    @NonNull
    public static List<String> filterListOfStrings(List<String> list, @NonNull String str) {
        ArrayList arrayList = new ArrayList();
        if (list != null && !list.isEmpty()) {
            for (String str2 : list) {
                if (str2 != null && str2.contains(str)) {
                    arrayList.add(str2);
                }
            }
        }
        return arrayList;
    }

    public static boolean getBooleanValue(String str) {
        if (str == null) {
            return false;
        }
        try {
            return Boolean.parseBoolean(str);
        } catch (Exception unused) {
            POBLog.error("POBUtils", "Cannot convert string %s to boolean", str);
            return false;
        }
    }

    public static Object getBuildConfigValue(Context context, String str) {
        try {
            return Class.forName(context.getPackageName() + ".BuildConfig").getField(str).get(null);
        } catch (Exception e) {
            POBLog.warn("POBUtils", "Build config value is not available, reason :%s", e.getCause());
            return null;
        }
    }

    public static int getDeviceOrientation(@NonNull Context context) {
        Configuration configuration;
        Resources resources = context.getResources();
        if (resources == null || (configuration = resources.getConfiguration()) == null) {
            return 0;
        }
        return configuration.orientation;
    }

    public static int getIntegerValue(String str) {
        if (str == null) {
            return 0;
        }
        try {
            return Integer.parseInt(str);
        } catch (Exception unused) {
            POBLog.error("POBUtils", "Cannot convert string %s to integer", str);
            return 0;
        }
    }

    public static com.pubmatic.sdk.common.f getInterstitialAdSize(@NonNull Context context) {
        int deviceOrientation = getDeviceOrientation(context);
        return isTablet(context) ? deviceOrientation == 2 ? com.pubmatic.sdk.common.f.INTERSTITIAL_1024x768 : com.pubmatic.sdk.common.f.INTERSTITIAL_768x1024 : deviceOrientation == 2 ? com.pubmatic.sdk.common.f.INTERSTITIAL_480x320 : com.pubmatic.sdk.common.f.INTERSTITIAL_320x480;
    }

    public static com.pubmatic.sdk.common.models.h getLocation(g gVar) {
        Location location;
        com.pubmatic.sdk.common.models.h hVar = (!com.pubmatic.sdk.common.i.getSdkConfig().isLocationAccessAllowed() || gVar == null || (location = gVar.getLocation()) == null) ? null : new com.pubmatic.sdk.common.models.h(location);
        return hVar == null ? com.pubmatic.sdk.common.i.getSdkConfig().getLocation() : hVar;
    }

    public static String getMappingKey(int i, Integer num) {
        if (num == null) {
            return String.valueOf(i);
        }
        return i + ":" + num;
    }

    public static int getRandomNumber(int i, int i2) {
        return i + ((int) (Math.random() * ((i2 - i) + 1)));
    }

    public static int getScreenHeight() {
        return convertPixelToDp(Resources.getSystem().getDisplayMetrics().heightPixels);
    }

    public static int getScreenWidth() {
        return convertPixelToDp(Resources.getSystem().getDisplayMetrics().widthPixels);
    }

    public static double getSeconds(String str) {
        if (str == null || str.isEmpty()) {
            return 0.0d;
        }
        String[] strArrSplit = str.split(":", -1);
        double d = 0.0d;
        for (int length = strArrSplit.length - 1; length >= 0; length--) {
            try {
                d += Double.parseDouble(strArrSplit[length]) * Math.pow(60.0d, (strArrSplit.length - 1) - length);
            } catch (NumberFormatException unused) {
                POBLog.error("POBUtils", "Invalid time value", new Object[0]);
                return 0.0d;
            }
        }
        return d;
    }

    public static int getTimeOffsetInMinutes() {
        Calendar calendar = Calendar.getInstance(Locale.getDefault());
        return (calendar.get(16) + calendar.get(15)) / 60000;
    }

    public static int getValidRefreshInterval(int i, int i2) {
        if (i <= 0) {
            return 0;
        }
        return i <= i2 ? i2 : i;
    }

    public static int getViewVisiblePixel(View view) {
        if (view == null) {
            return 0;
        }
        Rect rect = new Rect();
        if (!view.getGlobalVisibleRect(rect)) {
            return 0;
        }
        return rect.width() * rect.height();
    }

    public static int[] getViewXYPosition(View view) {
        int[] iArr = new int[2];
        view.getLocationOnScreen(iArr);
        iArr[0] = convertPixelToDp(iArr[0]);
        iArr[1] = convertPixelToDp(iArr[1]);
        return iArr;
    }

    public static float getVisiblePercent(View view) {
        if (view == null) {
            return DefinitionKt.NO_Float_VALUE;
        }
        if (!view.getGlobalVisibleRect(new Rect())) {
            return DefinitionKt.NO_Float_VALUE;
        }
        return ((r0.width() * r0.height()) * 100) / (view.getWidth() * view.getHeight());
    }

    public static boolean hasPermission(@NonNull Context context, @NonNull String str) {
        return context.checkCallingOrSelfPermission(str) == 0;
    }

    public static boolean isJsonArrayNullOrEmpty(JSONArray jSONArray) {
        return jSONArray == null || jSONArray.length() <= 0;
    }

    public static boolean isJsonObjectNullOrEmpty(JSONObject jSONObject) {
        return jSONObject == null || jSONObject.length() <= 0;
    }

    public static boolean isListNullOrEmpty(List<?> list) {
        return list == null || list.isEmpty();
    }

    public static boolean isNull(Object[] objArr) {
        if (objArr == null || objArr.length <= 0) {
            return true;
        }
        for (Object obj : objArr) {
            if (obj == null) {
                return true;
            }
        }
        return false;
    }

    public static boolean isNullOrEmpty(String str) {
        if (str != null) {
            return str.isEmpty();
        }
        return true;
    }

    public static boolean isStringValueNullOrEmpty(String str) {
        return str == null || str.isEmpty() || str.equals("null");
    }

    public static boolean isTablet(Context context) {
        return (context.getResources().getConfiguration().screenLayout & 15) >= 3;
    }

    public static boolean isValidPlayStoreUrl(String str) {
        if (str == null) {
            return false;
        }
        if (str.contains("play.google.com") || str.contains("market://launch") || str.contains("market://details")) {
            return str.contains("id=");
        }
        return false;
    }

    public static boolean isViewVisible(View view, int i) {
        return getViewVisiblePixel(view) >= i;
    }

    public static void logBidWinningStatus(boolean z, String str) {
        if (z) {
            POBLog.debug("POBUtils", "Bid win for partner - %s", str);
        } else {
            POBLog.debug("POBUtils", "AdServerWin", new Object[0]);
        }
    }

    public static boolean openExternalBrowser(Context context, String str) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(str));
            intent.addFlags(268435456);
            context.startActivity(intent);
            return true;
        } catch (Exception unused) {
            POBLog.error("POBUtils", "Open external browser %s", "Not able to parse url");
            return false;
        }
    }

    @NonNull
    public static String parseJsTracker(@NonNull List<String> list) {
        StringBuilder sb = new StringBuilder();
        for (String str : list) {
            if (str.startsWith("http")) {
                sb.append("<script src=\"" + str + "\"></script>");
            } else {
                sb.append(str);
            }
        }
        return "<!DOCTYPE HTML><html><head>" + ((Object) sb) + "</head></html>";
    }

    @NonNull
    public static Set<String> parseJsonArrayToSet(JSONArray jSONArray) throws JSONException {
        HashSet hashSet = new HashSet();
        if (jSONArray != null) {
            for (int i = 0; i < jSONArray.length(); i++) {
                hashSet.add(jSONArray.getString(i));
            }
        }
        return hashSet;
    }

    public static String readFromAssets(@NonNull Context context, @NonNull String str) throws IOException {
        try {
            InputStream inputStreamOpen = context.getAssets().open(str);
            byte[] bArr = new byte[inputStreamOpen.available()];
            inputStreamOpen.read(bArr);
            inputStreamOpen.close();
            return new String(bArr);
        } catch (IOException unused) {
            POBLog.error("POBUtils", AbstractC0147y.d("Failed to read file : ", str), new Object[0]);
            return null;
        }
    }

    @NonNull
    public static Context resolveWebViewContext(@NonNull Context context) {
        return context;
    }

    public static void runOnBackgroundThread(Runnable runnable) {
        if (Thread.currentThread() == Looper.getMainLooper().getThread()) {
            new Thread(runnable).start();
        } else {
            runnable.run();
        }
    }

    public static void runOnMainThread(Runnable runnable) {
        if (Thread.currentThread() != Looper.getMainLooper().getThread()) {
            new Handler(Looper.getMainLooper()).post(runnable);
        } else {
            runnable.run();
        }
    }
}
