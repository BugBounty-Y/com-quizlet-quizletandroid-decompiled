package com.facebook.internal;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.hardware.display.DisplayManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Parcel;
import android.os.StatFs;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.view.Display;
import android.webkit.CookieManager;
import android.webkit.CookieSyncManager;
import androidx.compose.animation.d0;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import com.facebook.FacebookRequestError;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.Regex;
import kotlin.text.StringsKt__StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/* loaded from: classes.dex */
public abstract class J {
    public static int a = 0;
    public static long b = -1;
    public static long c = -1;
    public static long d = -1;
    public static String e = "";
    public static String f = "";
    public static String g = "NoCarrier";
    public static String h = "";
    public static Locale i;

    public static final boolean A(androidx.fragment.app.I context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (Build.VERSION.SDK_INT >= 27) {
            return context.getPackageManager().hasSystemFeature("android.hardware.type.pc");
        }
        String DEVICE = Build.DEVICE;
        if (DEVICE == null) {
            return false;
        }
        Intrinsics.checkNotNullExpressionValue(DEVICE, "DEVICE");
        return new Regex(".+_cheets|cheets_.+").e(DEVICE);
    }

    public static final boolean B() {
        if (!com.facebook.internal.instrument.crashshield.a.b(J.class)) {
            try {
                JSONObject jSONObjectO = o();
                if (jSONObjectO != null) {
                    try {
                        JSONArray jSONArray = jSONObjectO.getJSONArray("data_processing_options");
                        int length = jSONArray.length();
                        for (int i2 = 0; i2 < length; i2++) {
                            String string = jSONArray.getString(i2);
                            Intrinsics.checkNotNullExpressionValue(string, "options.getString(i)");
                            String lowerCase = string.toLowerCase();
                            Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase()");
                            if (Intrinsics.b(lowerCase, "ldu")) {
                                return true;
                            }
                        }
                    } catch (Exception unused) {
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(J.class, th);
                return false;
            }
        }
        return false;
    }

    public static boolean C(Context context) throws ClassNotFoundException {
        Method methodV = v("com.google.android.gms.common.GooglePlayServicesUtil", "isGooglePlayServicesAvailable", Context.class);
        if (methodV != null) {
            Object objY = y(null, methodV, context);
            if ((objY instanceof Integer) && Intrinsics.b(objY, 0)) {
                return true;
            }
        }
        return false;
    }

    public static final boolean D(String str) {
        return str == null || str.length() == 0;
    }

    public static final boolean E(Uri uri) {
        if (uri != null) {
            return "http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()) || "fbstaging".equalsIgnoreCase(uri.getScheme());
        }
        return false;
    }

    public static final ArrayList F(JSONArray jsonArray) {
        Intrinsics.checkNotNullParameter(jsonArray, "jsonArray");
        ArrayList arrayList = new ArrayList();
        int length = jsonArray.length();
        for (int i2 = 0; i2 < length; i2++) {
            arrayList.add(jsonArray.getString(i2));
        }
        return arrayList;
    }

    public static final HashMap G(String str) throws JSONException {
        Intrinsics.checkNotNullParameter(str, "str");
        if (str.length() == 0) {
            return new HashMap();
        }
        try {
            HashMap map = new HashMap();
            JSONObject jSONObject = new JSONObject(str);
            Iterator<String> itKeys = jSONObject.keys();
            while (itKeys.hasNext()) {
                String key = itKeys.next();
                Intrinsics.checkNotNullExpressionValue(key, "key");
                String string = jSONObject.getString(key);
                Intrinsics.checkNotNullExpressionValue(string, "jsonObject.getString(key)");
                map.put(key, string);
            }
            return map;
        } catch (JSONException unused) {
            return new HashMap();
        }
    }

    public static final String H(Map map) throws JSONException {
        Intrinsics.checkNotNullParameter(map, "map");
        String string = "";
        if (map.isEmpty()) {
            return "";
        }
        try {
            JSONObject jSONObject = new JSONObject();
            for (Map.Entry entry : map.entrySet()) {
                jSONObject.put((String) entry.getKey(), (String) entry.getValue());
            }
            string = jSONObject.toString();
        } catch (JSONException unused) {
        }
        Intrinsics.checkNotNullExpressionValue(string, "{\n      try {\n        va…\n        \"\"\n      }\n    }");
        return string;
    }

    public static final Bundle I(String str) {
        Bundle bundle = new Bundle();
        if (!D(str)) {
            if (str == null) {
                throw new IllegalStateException("Required value was null.");
            }
            for (String str2 : (String[]) StringsKt__StringsKt.split$default(str, new String[]{"&"}, false, 0, 6, null).toArray(new String[0])) {
                String[] strArr = (String[]) StringsKt__StringsKt.split$default(str2, new String[]{SimpleComparison.EQUAL_TO_OPERATION}, false, 0, 6, null).toArray(new String[0]);
                try {
                    if (strArr.length == 2) {
                        bundle.putString(URLDecoder.decode(strArr[0], "UTF-8"), URLDecoder.decode(strArr[1], "UTF-8"));
                    } else if (strArr.length == 1) {
                        bundle.putString(URLDecoder.decode(strArr[0], "UTF-8"), "");
                    }
                } catch (UnsupportedEncodingException unused) {
                    com.facebook.o oVar = com.facebook.o.a;
                }
            }
        }
        return bundle;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void J(Bundle bundle, JSONArray jSONArray) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        if (jSONArray instanceof boolean[]) {
            bundle.putBooleanArray("media", (boolean[]) jSONArray);
            return;
        }
        if (jSONArray instanceof double[]) {
            bundle.putDoubleArray("media", (double[]) jSONArray);
            return;
        }
        if (jSONArray instanceof int[]) {
            bundle.putIntArray("media", (int[]) jSONArray);
        } else if (jSONArray instanceof long[]) {
            bundle.putLongArray("media", (long[]) jSONArray);
        } else {
            bundle.putString("media", jSONArray.toString());
        }
    }

    public static final HashMap K(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        int i2 = parcel.readInt();
        if (i2 < 0) {
            return null;
        }
        HashMap map = new HashMap();
        for (int i3 = 0; i3 < i2; i3++) {
            String string = parcel.readString();
            String string2 = parcel.readString();
            if (string != null && string2 != null) {
                map.put(string, string2);
            }
        }
        return map;
    }

    public static final String L(InputStream inputStream) throws Throwable {
        BufferedInputStream bufferedInputStream;
        Throwable th;
        InputStreamReader inputStreamReader;
        try {
            bufferedInputStream = new BufferedInputStream(inputStream);
            try {
                inputStreamReader = new InputStreamReader(bufferedInputStream);
                try {
                    StringBuilder sb = new StringBuilder();
                    char[] cArr = new char[2048];
                    while (true) {
                        int i2 = inputStreamReader.read(cArr);
                        if (i2 == -1) {
                            String string = sb.toString();
                            Intrinsics.checkNotNullExpressionValue(string, "{\n      bufferedInputStr…gBuilder.toString()\n    }");
                            d(bufferedInputStream);
                            d(inputStreamReader);
                            return string;
                        }
                        sb.append(cArr, 0, i2);
                    }
                } catch (Throwable th2) {
                    th = th2;
                    d(bufferedInputStream);
                    d(inputStreamReader);
                    throw th;
                }
            } catch (Throwable th3) {
                th = th3;
                inputStreamReader = null;
            }
        } catch (Throwable th4) {
            bufferedInputStream = null;
            th = th4;
            inputStreamReader = null;
        }
    }

    public static final void M(Runnable runnable) {
        try {
            com.facebook.o.c().execute(runnable);
        } catch (Exception unused) {
        }
    }

    public static final void N(Context appContext, JSONObject params) throws JSONException, PackageManager.NameNotFoundException {
        Locale locale;
        int i2;
        Display display;
        PackageInfo packageInfo;
        Intrinsics.checkNotNullParameter(params, "params");
        Intrinsics.checkNotNullParameter(appContext, "appContext");
        JSONArray jSONArray = new JSONArray();
        jSONArray.put("a2");
        int i3 = 0;
        if (b == -1 || System.currentTimeMillis() - b >= 1800000) {
            b = System.currentTimeMillis();
            try {
                TimeZone timeZone = TimeZone.getDefault();
                String displayName = timeZone.getDisplayName(timeZone.inDaylightTime(new Date()), 0);
                Intrinsics.checkNotNullExpressionValue(displayName, "tz.getDisplayName(tz.inD…(Date()), TimeZone.SHORT)");
                e = displayName;
                String id = timeZone.getID();
                Intrinsics.checkNotNullExpressionValue(id, "tz.id");
                f = id;
            } catch (AssertionError | Exception unused) {
            }
            if (Intrinsics.b(g, "NoCarrier")) {
                try {
                    Object systemService = appContext.getSystemService("phone");
                    Intrinsics.e(systemService, "null cannot be cast to non-null type android.telephony.TelephonyManager");
                    String networkOperatorName = ((TelephonyManager) systemService).getNetworkOperatorName();
                    Intrinsics.checkNotNullExpressionValue(networkOperatorName, "telephonyManager.networkOperatorName");
                    g = networkOperatorName;
                } catch (Exception unused2) {
                }
            }
            try {
                if ("mounted".equals(Environment.getExternalStorageState())) {
                    StatFs statFs = new StatFs(Environment.getExternalStorageDirectory().getPath());
                    c = statFs.getBlockCount() * statFs.getBlockSize();
                }
                c = Math.round(c / 1.073741824E9d);
            } catch (Exception unused3) {
            }
            try {
                if ("mounted".equals(Environment.getExternalStorageState())) {
                    StatFs statFs2 = new StatFs(Environment.getExternalStorageDirectory().getPath());
                    d = statFs2.getAvailableBlocks() * statFs2.getBlockSize();
                }
                d = Math.round(d / 1.073741824E9d);
            } catch (Exception unused4) {
            }
        }
        String packageName = appContext.getPackageName();
        int i4 = -1;
        try {
            packageInfo = appContext.getPackageManager().getPackageInfo(packageName, 0);
        } catch (PackageManager.NameNotFoundException unused5) {
        }
        if (packageInfo == null) {
            return;
        }
        i4 = packageInfo.versionCode;
        h = packageInfo.versionName;
        jSONArray.put(packageName);
        jSONArray.put(i4);
        jSONArray.put(h);
        jSONArray.put(Build.VERSION.RELEASE);
        jSONArray.put(Build.MODEL);
        try {
            locale = appContext.getResources().getConfiguration().locale;
        } catch (Exception unused6) {
            locale = Locale.getDefault();
        }
        i = locale;
        StringBuilder sb = new StringBuilder();
        Locale locale2 = i;
        String language = locale2 != null ? locale2.getLanguage() : null;
        if (language == null) {
            language = "";
        }
        sb.append(language);
        sb.append('_');
        Locale locale3 = i;
        String country = locale3 != null ? locale3.getCountry() : null;
        sb.append(country != null ? country : "");
        jSONArray.put(sb.toString());
        jSONArray.put(e);
        jSONArray.put(g);
        double d2 = 0.0d;
        try {
            Object systemService2 = appContext.getSystemService("display");
            DisplayManager displayManager = systemService2 instanceof DisplayManager ? (DisplayManager) systemService2 : null;
            display = displayManager != null ? displayManager.getDisplay(0) : null;
        } catch (Exception unused7) {
        }
        if (display != null) {
            DisplayMetrics displayMetrics = new DisplayMetrics();
            display.getMetrics(displayMetrics);
            int i5 = displayMetrics.widthPixels;
            try {
                i3 = displayMetrics.heightPixels;
                d2 = displayMetrics.density;
            } catch (Exception unused8) {
            }
            i2 = i3;
            i3 = i5;
        } else {
            i2 = 0;
        }
        jSONArray.put(i3);
        jSONArray.put(i2);
        jSONArray.put(new DecimalFormat("#.##").format(d2));
        int i6 = a;
        if (i6 <= 0) {
            try {
                File[] fileArrListFiles = new File("/sys/devices/system/cpu/").listFiles(new H(0));
                if (fileArrListFiles != null) {
                    a = fileArrListFiles.length;
                }
            } catch (Exception unused9) {
            }
            if (a <= 0) {
                a = Math.max(Runtime.getRuntime().availableProcessors(), 1);
            }
            i6 = a;
        }
        jSONArray.put(i6);
        jSONArray.put(c);
        jSONArray.put(d);
        jSONArray.put(f);
        params.put("extinfo", jSONArray.toString());
    }

    public static final String O(String str) {
        if (str == null) {
            return null;
        }
        byte[] bytes = str.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        return x("SHA-256", bytes);
    }

    public static final void P(Parcel parcel, Map map) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        if (map == null) {
            parcel.writeInt(-1);
            return;
        }
        parcel.writeInt(map.size());
        for (Map.Entry entry : map.entrySet()) {
            String str = (String) entry.getKey();
            String str2 = (String) entry.getValue();
            parcel.writeString(str);
            parcel.writeString(str2);
        }
    }

    public static final Uri a(String str, String str2, Bundle bundle) {
        Uri.Builder builder = new Uri.Builder();
        builder.scheme("https");
        builder.authority(str);
        builder.path(str2);
        if (bundle != null) {
            for (String str3 : bundle.keySet()) {
                Object obj = bundle.get(str3);
                if (obj instanceof String) {
                    builder.appendQueryParameter(str3, (String) obj);
                }
            }
        }
        Uri uriBuild = builder.build();
        Intrinsics.checkNotNullExpressionValue(uriBuild, "builder.build()");
        return uriBuild;
    }

    public static void b(Context context, String str) {
        CookieSyncManager.createInstance(context).sync();
        CookieManager cookieManager = CookieManager.getInstance();
        String cookie = cookieManager.getCookie(str);
        if (cookie == null) {
            return;
        }
        for (String str2 : (String[]) StringsKt__StringsKt.split$default(cookie, new String[]{";"}, false, 0, 6, null).toArray(new String[0])) {
            String[] strArr = (String[]) StringsKt__StringsKt.split$default(str2, new String[]{SimpleComparison.EQUAL_TO_OPERATION}, false, 0, 6, null).toArray(new String[0]);
            if (strArr.length > 0) {
                StringBuilder sb = new StringBuilder();
                String str3 = strArr[0];
                int length = str3.length() - 1;
                int i2 = 0;
                boolean z = false;
                while (i2 <= length) {
                    boolean z2 = Intrinsics.g(str3.charAt(!z ? i2 : length), 32) <= 0;
                    if (z) {
                        if (!z2) {
                            break;
                        } else {
                            length--;
                        }
                    } else if (z2) {
                        i2++;
                    } else {
                        z = true;
                    }
                }
                sb.append(str3.subSequence(i2, length + 1).toString());
                sb.append("=;expires=Sat, 1 Jan 2000 00:00:01 UTC;");
                cookieManager.setCookie(str, sb.toString());
            }
        }
        cookieManager.removeExpiredCookie();
    }

    public static final void c(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            b(context, "facebook.com");
            b(context, ".facebook.com");
            b(context, "https://facebook.com");
            b(context, "https://.facebook.com");
        } catch (Exception unused) {
        }
    }

    public static final void d(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException unused) {
            }
        }
    }

    public static final String e(String str) {
        return D(str) ? "" : str;
    }

    public static final HashSet f(JSONArray jSONArray) throws JSONException {
        if (jSONArray == null || jSONArray.length() == 0) {
            return null;
        }
        HashSet hashSet = new HashSet();
        int length = jSONArray.length();
        for (int i2 = 0; i2 < length; i2++) {
            String string = jSONArray.getString(i2);
            Intrinsics.checkNotNullExpressionValue(string, "jsonArray.getString(i)");
            hashSet.add(string);
        }
        return hashSet;
    }

    public static final ArrayList g(JSONArray jsonArray) throws JSONException {
        Intrinsics.checkNotNullParameter(jsonArray, "jsonArray");
        try {
            ArrayList arrayList = new ArrayList();
            int length = jsonArray.length();
            for (int i2 = 0; i2 < length; i2++) {
                String string = jsonArray.getString(i2);
                Intrinsics.checkNotNullExpressionValue(string, "jsonArray.getString(i)");
                arrayList.add(string);
            }
            return arrayList;
        } catch (JSONException unused) {
            return new ArrayList();
        }
    }

    public static final HashMap h(JSONObject jsonObject) throws JSONException {
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        HashMap map = new HashMap();
        JSONArray jSONArrayNames = jsonObject.names();
        if (jSONArrayNames != null) {
            int length = jSONArrayNames.length();
            for (int i2 = 0; i2 < length; i2++) {
                try {
                    String string = jSONArrayNames.getString(i2);
                    Intrinsics.checkNotNullExpressionValue(string, "keys.getString(i)");
                    Object value = jsonObject.get(string);
                    if (value instanceof JSONObject) {
                        value = h((JSONObject) value);
                    }
                    Intrinsics.checkNotNullExpressionValue(value, "value");
                    map.put(string, value);
                } catch (JSONException unused) {
                }
            }
        }
        return map;
    }

    public static final HashMap i(JSONObject jsonObject) {
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        HashMap map = new HashMap();
        Iterator<String> itKeys = jsonObject.keys();
        while (itKeys.hasNext()) {
            String key = itKeys.next();
            String strOptString = jsonObject.optString(key);
            if (strOptString != null) {
                Intrinsics.checkNotNullExpressionValue(key, "key");
                map.put(key, strOptString);
            }
        }
        return map;
    }

    public static final int j(InputStream inputStream, FilterOutputStream outputStream) {
        BufferedInputStream bufferedInputStream;
        Intrinsics.checkNotNullParameter(outputStream, "outputStream");
        BufferedInputStream bufferedInputStream2 = null;
        try {
            bufferedInputStream = new BufferedInputStream(inputStream);
        } catch (Throwable th) {
            th = th;
        }
        try {
            byte[] bArr = new byte[8192];
            int i2 = 0;
            while (true) {
                int i3 = bufferedInputStream.read(bArr);
                if (i3 == -1) {
                    break;
                }
                outputStream.write(bArr, 0, i3);
                i2 += i3;
            }
            bufferedInputStream.close();
            if (inputStream != null) {
                inputStream.close();
            }
            return i2;
        } catch (Throwable th2) {
            th = th2;
            bufferedInputStream2 = bufferedInputStream;
            if (bufferedInputStream2 != null) {
                bufferedInputStream2.close();
            }
            if (inputStream != null) {
                inputStream.close();
            }
            throw th;
        }
    }

    public static final void k(HttpURLConnection httpURLConnection) {
        if (httpURLConnection != null) {
            httpURLConnection.disconnect();
        }
    }

    public static final String l(Context context) {
        if (context == null) {
            return "null";
        }
        if (context == context.getApplicationContext()) {
            return DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
        String simpleName = context.getClass().getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "{\n      context.javaClass.simpleName\n    }");
        return simpleName;
    }

    public static final String m(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            com.facebook.o oVar = com.facebook.o.a;
            AbstractC1554i.k();
            String str = com.facebook.o.e;
            if (str != null) {
                return str;
            }
            ApplicationInfo applicationInfo = context.getApplicationInfo();
            int i2 = applicationInfo.labelRes;
            if (i2 == 0) {
                return applicationInfo.nonLocalizedLabel.toString();
            }
            String string = context.getString(i2);
            Intrinsics.checkNotNullExpressionValue(string, "context.getString(stringId)");
            return string;
        } catch (Exception unused) {
            return "";
        }
    }

    public static final Date n(Bundle bundle, String str, Date dateBase) throws NumberFormatException {
        long jLongValue;
        Intrinsics.checkNotNullParameter(dateBase, "dateBase");
        if (bundle == null) {
            return null;
        }
        Object obj = bundle.get(str);
        if (obj instanceof Long) {
            jLongValue = ((Number) obj).longValue();
        } else {
            if (!(obj instanceof String)) {
                return null;
            }
            try {
                jLongValue = Long.parseLong((String) obj);
            } catch (NumberFormatException unused) {
                return null;
            }
        }
        if (jLongValue == 0) {
            return new Date(Long.MAX_VALUE);
        }
        return new Date((jLongValue * 1000) + dateBase.getTime());
    }

    public static final JSONObject o() {
        if (com.facebook.internal.instrument.crashshield.a.b(J.class)) {
            return null;
        }
        try {
            String string = com.facebook.o.a().getSharedPreferences("com.facebook.sdk.DataProcessingOptions", 0).getString("data_processing_options", null);
            if (string != null) {
                try {
                    return new JSONObject(string);
                } catch (JSONException unused) {
                }
            }
            return null;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(J.class, th);
            return null;
        }
    }

    public static final String p() {
        return d0.s(new Object[]{com.facebook.o.q}, 1, "m.%s", "format(format, *args)");
    }

    public static final void q(final I callback, final String accessToken) {
        String str;
        Intrinsics.checkNotNullParameter(accessToken, "accessToken");
        Intrinsics.checkNotNullParameter(callback, "callback");
        ConcurrentHashMap concurrentHashMap = E.a;
        Intrinsics.checkNotNullParameter(accessToken, "accessToken");
        JSONObject jSONObject = (JSONObject) E.a.get(accessToken);
        if (jSONObject != null) {
            callback.b(jSONObject);
            return;
        }
        com.facebook.q qVar = new com.facebook.q() { // from class: com.facebook.internal.G
            @Override // com.facebook.q
            public final void a(com.facebook.w response) {
                I callback2 = callback;
                Intrinsics.checkNotNullParameter(callback2, "$callback");
                String key = accessToken;
                Intrinsics.checkNotNullParameter(key, "$accessToken");
                Intrinsics.checkNotNullParameter(response, "response");
                FacebookRequestError facebookRequestError = response.c;
                if (facebookRequestError != null) {
                    callback2.c(facebookRequestError.i);
                    return;
                }
                JSONObject value = response.d;
                if (value == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                ConcurrentHashMap concurrentHashMap2 = E.a;
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(value, "value");
                E.a.put(key, value);
                callback2.b(value);
            }
        };
        com.facebook.x xVar = com.facebook.x.a;
        Bundle bundle = new Bundle();
        Date date = AccessToken.l;
        AccessToken accessTokenC = com.google.android.gms.internal.mlkit_vision_common.D.c();
        if (accessTokenC == null || (str = accessTokenC.k) == null) {
            str = "facebook";
        }
        bundle.putString("fields", str.equals("instagram") ? "id,name,profile_picture" : "id,name,first_name,middle_name,last_name");
        bundle.putString("access_token", accessToken);
        com.facebook.t tVar = new com.facebook.t(null, "me", null, null, new com.facebook.r(0));
        Intrinsics.checkNotNullParameter(bundle, "<set-?>");
        tVar.d = bundle;
        tVar.h = xVar;
        tVar.j(qVar);
        tVar.d();
    }

    public static final String r() {
        return d0.s(new Object[]{com.facebook.o.p}, 1, "m.%s", "format(format, *args)");
    }

    public static void s(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (C1549d.a() != null) {
            C1549d.a();
            return;
        }
        C1549d c1549d = new C1549d(context);
        if (!com.facebook.internal.instrument.crashshield.a.b(C1549d.class)) {
            try {
                if (!com.facebook.internal.instrument.crashshield.a.b(c1549d)) {
                    try {
                        androidx.localbroadcastmanager.content.b bVarA = androidx.localbroadcastmanager.content.b.a((Context) c1549d.b);
                        Intrinsics.checkNotNullExpressionValue(bVarA, "getInstance(applicationContext)");
                        bVarA.b(c1549d, new IntentFilter("com.parse.bolts.measurement_event"));
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(c1549d, th);
                    }
                }
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(C1549d.class, th2);
            }
        }
        if (!com.facebook.internal.instrument.crashshield.a.b(C1549d.class)) {
            try {
                C1549d.c = c1549d;
            } catch (Throwable th3) {
                com.facebook.internal.instrument.crashshield.a.a(C1549d.class, th3);
            }
        }
        C1549d.a();
    }

    public static final String t(Context context) {
        Intrinsics.checkNotNullParameter("context", "name");
        return com.facebook.o.b();
    }

    public static final Method u(Class clazz, String methodName, Class... parameterTypes) {
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        Intrinsics.checkNotNullParameter(methodName, "methodName");
        Intrinsics.checkNotNullParameter(parameterTypes, "parameterTypes");
        try {
            return clazz.getMethod(methodName, (Class[]) Arrays.copyOf(parameterTypes, parameterTypes.length));
        } catch (NoSuchMethodException unused) {
            return null;
        }
    }

    public static final Method v(String className, String methodName, Class... parameterTypes) throws ClassNotFoundException {
        Intrinsics.checkNotNullParameter(className, "className");
        Intrinsics.checkNotNullParameter(methodName, "methodName");
        Intrinsics.checkNotNullParameter(parameterTypes, "parameterTypes");
        try {
            Class<?> clazz = Class.forName(className);
            Intrinsics.checkNotNullExpressionValue(clazz, "clazz");
            return u(clazz, methodName, (Class[]) Arrays.copyOf(parameterTypes, parameterTypes.length));
        } catch (ClassNotFoundException unused) {
            return null;
        }
    }

    public static final Object w(JSONObject jsonObject, String str, String str2) throws JSONException {
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        Object objOpt = jsonObject.opt(str);
        if (objOpt != null && (objOpt instanceof String)) {
            objOpt = new JSONTokener((String) objOpt).nextValue();
        }
        if (objOpt == null || (objOpt instanceof JSONObject) || (objOpt instanceof JSONArray)) {
            return objOpt;
        }
        if (str2 == null) {
            throw new FacebookException("Got an unexpected non-JSON object.");
        }
        JSONObject jSONObject = new JSONObject();
        jSONObject.putOpt(str2, objOpt);
        return jSONObject;
    }

    public static String x(String str, byte[] bArr) throws NoSuchAlgorithmException {
        try {
            MessageDigest hash = MessageDigest.getInstance(str);
            Intrinsics.checkNotNullExpressionValue(hash, "hash");
            hash.update(bArr);
            byte[] digest = hash.digest();
            StringBuilder sb = new StringBuilder();
            Intrinsics.checkNotNullExpressionValue(digest, "digest");
            for (byte b2 : digest) {
                sb.append(Integer.toHexString((b2 >> 4) & 15));
                sb.append(Integer.toHexString(b2 & 15));
            }
            String string = sb.toString();
            Intrinsics.checkNotNullExpressionValue(string, "builder.toString()");
            return string;
        } catch (NoSuchAlgorithmException unused) {
            return null;
        }
    }

    public static final Object y(Object obj, Method method, Object... args) {
        Intrinsics.checkNotNullParameter(method, "method");
        Intrinsics.checkNotNullParameter(args, "args");
        try {
            return method.invoke(obj, Arrays.copyOf(args, args.length));
        } catch (IllegalAccessException | InvocationTargetException unused) {
            return null;
        }
    }

    public static final boolean z() {
        try {
            Intent intent = new Intent("android.intent.action.VIEW");
            String str = String.format("fb%s://applinks", Arrays.copyOf(new Object[]{com.facebook.o.b()}, 1));
            Intrinsics.checkNotNullExpressionValue(str, "format(format, *args)");
            intent.setData(Uri.parse(str));
            Context contextA = com.facebook.o.a();
            PackageManager packageManager = contextA.getPackageManager();
            String packageName = contextA.getPackageName();
            List<ResolveInfo> listQueryIntentActivities = packageManager.queryIntentActivities(intent, 65536);
            Intrinsics.checkNotNullExpressionValue(listQueryIntentActivities, "packageManager.queryInte…nager.MATCH_DEFAULT_ONLY)");
            Iterator<ResolveInfo> it2 = listQueryIntentActivities.iterator();
            while (it2.hasNext()) {
                if (Intrinsics.b(packageName, it2.next().activityInfo.packageName)) {
                    return true;
                }
            }
            return false;
        } catch (Exception unused) {
            return false;
        }
    }
}
