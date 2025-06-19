package com.appsflyer.internal;

import android.annotation.SuppressLint;
import android.app.UiModeManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.os.SystemClock;
import android.provider.Settings;
import android.text.TextUtils;
import android.widget.ExpandableListView;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.glance.appwidget.protobuf.Z;
import com.amazon.device.ads.DtbDeviceData;
import com.appsflyer.AFLogger;
import com.appsflyer.AdRevenueScheme;
import com.appsflyer.AppsFlyerProperties;
import com.appsflyer.internal.AFg1uSDK;
import com.comscore.streaming.ContentType;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.p;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AFg1oSDK implements AFg1qSDK {
    private static int $10 = 0;
    private static int $11 = 1;
    private static int d = 1;
    private static int w;

    @NotNull
    private final AFj1lSDK AFAdRevenueData;

    @NotNull
    private final kotlin.k AFLogger;

    @NotNull
    private final AFh1vSDK areAllFieldsValid;

    @NotNull
    private final AFi1tSDK component1;

    @NotNull
    private final AFg1vSDK component2;

    @NotNull
    private final AFc1pSDK component3;

    @NotNull
    private final AFc1qSDK component4;

    @NotNull
    private final AFc1kSDK copy;

    @NotNull
    private final kotlin.k copydefault;

    @NotNull
    private final AFf1gSDK equals;

    @NotNull
    private final String getCurrencyIso4217Code;

    @NotNull
    private final AFg1uSDK getMediationNetwork;

    @NotNull
    private final Context getMonetizationNetwork;

    @NotNull
    private final AFi1lSDK getRevenue;

    @NotNull
    private final AFg1xSDK hashCode;

    @NotNull
    private final AFc1iSDK toString;
    private static char[] registerClient = {8582, 8581, 8594, 8595, 8592, 8312, 8589, 8593, 8606, 8579, 8580, 8288, 8577, 8578, 8576};
    private static int AFKeystoreWrapper = -771284948;
    private static boolean AFInAppEventParameterName = true;
    private static boolean AFInAppEventType = true;

    @Metadata
    /* renamed from: com.appsflyer.internal.AFg1oSDK$1, reason: invalid class name */
    public static final class AnonymousClass1 extends r implements Function0<SimpleDateFormat> {
        public static final AnonymousClass1 AFAdRevenueData = new AnonymousClass1();

        public AnonymousClass1() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        /* renamed from: AFAdRevenueData, reason: merged with bridge method [inline-methods] */
        public final SimpleDateFormat invoke() {
            return new SimpleDateFormat("yyyy-MM-dd_HHmmssZ", Locale.US);
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.internal.AFg1oSDK$4, reason: invalid class name */
    public static final class AnonymousClass4 extends r implements Function0<AppsFlyerProperties> {
        public static final AnonymousClass4 getMediationNetwork = new AnonymousClass4();

        public AnonymousClass4() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        /* renamed from: AFAdRevenueData, reason: merged with bridge method [inline-methods] */
        public final AppsFlyerProperties invoke() {
            return AppsFlyerProperties.getInstance();
        }
    }

    public AFg1oSDK(@NotNull String str, @NotNull Context context, @NotNull AFi1lSDK aFi1lSDK, @NotNull AFg1uSDK aFg1uSDK, @NotNull AFj1lSDK aFj1lSDK, @NotNull AFg1vSDK aFg1vSDK, @NotNull AFh1vSDK aFh1vSDK, @NotNull AFc1qSDK aFc1qSDK, @NotNull AFc1pSDK aFc1pSDK, @NotNull AFi1tSDK aFi1tSDK, @NotNull AFf1gSDK aFf1gSDK, @NotNull AFc1iSDK aFc1iSDK, @NotNull AFg1xSDK aFg1xSDK, @NotNull AFc1kSDK aFc1kSDK) {
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(context, "");
        Intrinsics.checkNotNullParameter(aFi1lSDK, "");
        Intrinsics.checkNotNullParameter(aFg1uSDK, "");
        Intrinsics.checkNotNullParameter(aFj1lSDK, "");
        Intrinsics.checkNotNullParameter(aFg1vSDK, "");
        Intrinsics.checkNotNullParameter(aFh1vSDK, "");
        Intrinsics.checkNotNullParameter(aFc1qSDK, "");
        Intrinsics.checkNotNullParameter(aFc1pSDK, "");
        Intrinsics.checkNotNullParameter(aFi1tSDK, "");
        Intrinsics.checkNotNullParameter(aFf1gSDK, "");
        Intrinsics.checkNotNullParameter(aFc1iSDK, "");
        Intrinsics.checkNotNullParameter(aFg1xSDK, "");
        Intrinsics.checkNotNullParameter(aFc1kSDK, "");
        this.getCurrencyIso4217Code = str;
        this.getMonetizationNetwork = context;
        this.getRevenue = aFi1lSDK;
        this.getMediationNetwork = aFg1uSDK;
        this.AFAdRevenueData = aFj1lSDK;
        this.component2 = aFg1vSDK;
        this.areAllFieldsValid = aFh1vSDK;
        this.component4 = aFc1qSDK;
        this.component3 = aFc1pSDK;
        this.component1 = aFi1tSDK;
        this.equals = aFf1gSDK;
        this.toString = aFc1iSDK;
        this.hashCode = aFg1xSDK;
        this.copy = aFc1kSDK;
        this.copydefault = kotlin.l.b(AnonymousClass4.getMediationNetwork);
        this.AFLogger = kotlin.l.b(AnonymousClass1.AFAdRevenueData);
    }

    private static /* synthetic */ Object AFAdRevenueData(Object[] objArr) {
        boolean zB = false;
        AFg1oSDK aFg1oSDK = (AFg1oSDK) objArr[0];
        AFh1rSDK aFh1rSDK = (AFh1rSDK) objArr[1];
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        if (aFg1oSDK.component3.component4()) {
            AFh1oSDK aFh1oSDK = aFg1oSDK.component3.getCurrencyIso4217Code.component3;
            if (aFh1oSDK == null) {
                return null;
            }
            String str = aFh1oSDK.areAllFieldsValid;
            if (str != null) {
                d = (w + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION) % 128;
                if (str.length() != 0) {
                    aFh1rSDK.getMediationNetwork("gaidError", aFh1oSDK.areAllFieldsValid);
                    w = (d + 31) % 128;
                }
            }
            String str2 = aFh1oSDK.AFAdRevenueData;
            if (str2 != null && aFh1oSDK.getMonetizationNetwork != null) {
                aFh1rSDK.getMediationNetwork("advertiserId", str2);
                aFh1rSDK.getMediationNetwork("advertiserIdEnabled", String.valueOf(aFh1oSDK.getMonetizationNetwork));
                aFh1rSDK.getMediationNetwork("isGaidWithGps", String.valueOf(aFh1oSDK.getMediationNetwork));
            }
        } else {
            Map<String, Object> revenue = AFa1tSDK.getRevenue(aFh1rSDK.AFAdRevenueData);
            Intrinsics.checkNotNullExpressionValue(revenue, "");
            revenue.put("ad_ids_disabled", Boolean.TRUE);
        }
        AFh1oSDK aFh1oSDK2 = aFg1oSDK.component3.getCurrencyIso4217Code.component3;
        if (aFh1oSDK2 != null) {
            int i = d + 23;
            w = i % 128;
            if (i % 2 != 0) {
                Intrinsics.b(aFh1oSDK2.component2, Boolean.TRUE);
                throw null;
            }
            zB = Intrinsics.b(aFh1oSDK2.component2, Boolean.TRUE);
        }
        aFh1rSDK.getMediationNetwork("GAID_retry", String.valueOf(zB));
        if (B.j(AFe1mSDK.CONVERSION, AFe1mSDK.LAUNCH).contains(aFh1rSDK.getCurrencyIso4217Code())) {
            d = (w + 97) % 128;
            AFd1hSDK aFd1hSDK = aFg1oSDK.copy.component4;
            if (aFd1hSDK != null) {
                Map<String, Object> revenue2 = AFa1tSDK.getRevenue(aFh1rSDK.AFAdRevenueData);
                Intrinsics.checkNotNullExpressionValue(revenue2, "");
                revenue2.put("fetchAdIdLatency", Long.valueOf(aFd1hSDK.getRevenue));
                return null;
            }
        }
        int i2 = w + 35;
        d = i2 % 128;
        if (i2 % 2 != 0) {
            return null;
        }
        throw null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @SuppressLint({"HardwareIds"})
    private final String AFInAppEventParameterName() {
        String str;
        int i = w + 67;
        d = i % 128;
        int i2 = i % 2;
        try {
        } catch (Exception e) {
            AFLogger.afErrorLog(e.getMessage(), e);
            str = i2;
        }
        if (i2 == 0) {
            this.component4.AFAdRevenueData("androidIdCached", (String) null);
            Settings.Secure.getString(this.getMonetizationNetwork.getContentResolver(), "android_id");
            throw null;
        }
        String strAFAdRevenueData = this.component4.AFAdRevenueData("androidIdCached", (String) null);
        String string = Settings.Secure.getString(this.getMonetizationNetwork.getContentResolver(), "android_id");
        str = strAFAdRevenueData;
        if (string != null) {
            return string;
        }
        if (str == 0) {
            return null;
        }
        d = (w + 73) % 128;
        AFLogger.afDebugLog("use cached AndroidId: ".concat(str));
        int i3 = d + 125;
        w = i3 % 128;
        if (i3 % 2 != 0) {
            int i4 = 82 / 0;
        }
        return str;
    }

    private static void AFInAppEventType(@NotNull Map<String, Object> map) {
        int i = d + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION;
        w = i % 128;
        if (i % 2 != 0) {
            Intrinsics.checkNotNullParameter(map, "");
            AFa1zSDK.getCurrencyIso4217Code();
            AFa1zSDK.getRevenue();
            throw null;
        }
        Intrinsics.checkNotNullParameter(map, "");
        Object currencyIso4217Code = AFa1zSDK.getCurrencyIso4217Code();
        String revenue = AFa1zSDK.getRevenue();
        if (currencyIso4217Code == null || revenue == null || Integer.parseInt(revenue) <= 0) {
            return;
        }
        int i2 = w + 27;
        d = i2 % 128;
        if (i2 % 2 != 0) {
            map.put("reinstallCounter", revenue);
            map.put("originalAppsflyerId", currencyIso4217Code);
        } else {
            map.put("reinstallCounter", revenue);
            map.put("originalAppsflyerId", currencyIso4217Code);
            throw null;
        }
    }

    private void AFKeystoreWrapper(@NotNull Map<String, Object> map) {
        int i = w + 111;
        d = i % 128;
        if (i % 2 == 0) {
            Intrinsics.checkNotNullParameter(map, "");
            ((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getString(AppsFlyerProperties.EXTENSION);
            throw null;
        }
        Intrinsics.checkNotNullParameter(map, "");
        String string = ((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getString(AppsFlyerProperties.EXTENSION);
        if (string != null) {
            w = (d + 125) % 128;
            if (string.length() == 0) {
                return;
            }
            map.put(AppsFlyerProperties.EXTENSION, string);
        }
    }

    private void AFLogger(@NotNull Map<String, Object> map) throws PackageManager.NameNotFoundException {
        getMediationNetwork(new Object[]{this, map}, -140518465, 140518471, System.identityHashCode(this));
    }

    private static void a(String str, int[] iArr, String str2, int i, Object[] objArr) throws UnsupportedEncodingException {
        int i2;
        char[] charArray = str2;
        if (str2 != null) {
            $11 = ($10 + 17) % 128;
            charArray = str2.toCharArray();
        }
        char[] cArr = charArray;
        byte[] bytes = str;
        if (str != null) {
            bytes = str.getBytes("ISO-8859-1");
        }
        byte[] bArr = bytes;
        AFk1nSDK aFk1nSDK = new AFk1nSDK();
        char[] cArr2 = registerClient;
        if (cArr2 != null) {
            $11 = ($10 + ContentType.LIVE) % 128;
            int length = cArr2.length;
            char[] cArr3 = new char[length];
            for (int i3 = 0; i3 < length; i3++) {
                cArr3[i3] = (char) (cArr2[i3] ^ (-5879130172463570806L));
            }
            cArr2 = cArr3;
        }
        int i4 = (int) ((-5879130172463570806L) ^ AFKeystoreWrapper);
        if (AFInAppEventType) {
            int length2 = bArr.length;
            aFk1nSDK.getMonetizationNetwork = length2;
            char[] cArr4 = new char[length2];
            aFk1nSDK.AFAdRevenueData = 0;
            while (true) {
                int i5 = aFk1nSDK.AFAdRevenueData;
                int i6 = aFk1nSDK.getMonetizationNetwork;
                if (i5 >= i6) {
                    objArr[0] = new String(cArr4);
                    return;
                } else {
                    cArr4[i5] = (char) (cArr2[bArr[(i6 - 1) - i5] + i] - i4);
                    aFk1nSDK.AFAdRevenueData = i5 + 1;
                }
            }
        } else if (AFInAppEventParameterName) {
            $10 = ($11 + 81) % 128;
            int length3 = cArr.length;
            aFk1nSDK.getMonetizationNetwork = length3;
            char[] cArr5 = new char[length3];
            aFk1nSDK.AFAdRevenueData = 0;
            while (true) {
                int i7 = aFk1nSDK.AFAdRevenueData;
                int i8 = aFk1nSDK.getMonetizationNetwork;
                if (i7 >= i8) {
                    objArr[0] = new String(cArr5);
                    return;
                }
                int i9 = $10 + 13;
                $11 = i9 % 128;
                if (i9 % 2 == 0) {
                    cArr5[i7] = (char) (cArr2[cArr[i8 * i7] - i] / i4);
                    i2 = i7 % 0;
                } else {
                    cArr5[i7] = (char) (cArr2[cArr[(i8 - 1) - i7] - i] - i4);
                    i2 = i7 + 1;
                }
                aFk1nSDK.AFAdRevenueData = i2;
            }
        } else {
            int length4 = iArr.length;
            aFk1nSDK.getMonetizationNetwork = length4;
            char[] cArr6 = new char[length4];
            aFk1nSDK.AFAdRevenueData = 0;
            while (true) {
                int i10 = aFk1nSDK.AFAdRevenueData;
                int i11 = aFk1nSDK.getMonetizationNetwork;
                if (i10 >= i11) {
                    objArr[0] = new String(cArr6);
                    return;
                } else {
                    cArr6[i10] = (char) (cArr2[iArr[(i11 - 1) - i10] - i] - i4);
                    aFk1nSDK.AFAdRevenueData = i10 + 1;
                }
            }
        }
    }

    private void afDebugLog(@NotNull Map<String, Object> map) {
        String currencyIso4217Code;
        int i = w + 111;
        d = i % 128;
        if (i % 2 == 0) {
            Intrinsics.checkNotNullParameter(map, "");
            if (!((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getBoolean(AppsFlyerProperties.COLLECT_FACEBOOK_ATTR_ID, true)) {
                return;
            }
        } else {
            Intrinsics.checkNotNullParameter(map, "");
            if (!((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getBoolean(AppsFlyerProperties.COLLECT_FACEBOOK_ATTR_ID, true)) {
                return;
            }
        }
        try {
            this.getMonetizationNetwork.getPackageManager().getApplicationInfo("com.facebook.katana", 0);
            currencyIso4217Code = this.component3.getCurrencyIso4217Code(this.getMonetizationNetwork);
        } catch (Throwable unused) {
            currencyIso4217Code = null;
        }
        if (currencyIso4217Code != null) {
            int i2 = d + ContentType.LIVE;
            w = i2 % 128;
            if (i2 % 2 == 0) {
                map.put("fb", currencyIso4217Code);
            } else {
                map.put("fb", currencyIso4217Code);
                throw null;
            }
        }
    }

    private void afErrorLog(@NotNull Map<String, Object> map) {
        int i = d + 89;
        w = i % 128;
        if (i % 2 != 0) {
            Intrinsics.checkNotNullParameter(map, "");
            this.copy.AFAdRevenueData();
            throw null;
        }
        Intrinsics.checkNotNullParameter(map, "");
        if (!this.copy.AFAdRevenueData()) {
            AFb1gSDK aFb1gSDK = this.copy.toString;
            if (aFb1gSDK != null) {
                w = (d + 89) % 128;
                map.put("app_set_id", V.f(new Pair("scope", Integer.valueOf(aFb1gSDK.AFAdRevenueData)), new Pair("id", aFb1gSDK.getMonetizationNetwork)));
                return;
            }
            return;
        }
        map.put("app_set_id", U.b(new Pair("app_set_id_disabled", Boolean.TRUE)));
        if (this.copy.toString == null) {
            AFg1gSDK.i$default(AFLogger.INSTANCE, AFg1cSDK.APP_SET_ID, "App Set ID collection is disabled. Skipping inclusion in the event payload.", false, 4, null);
            return;
        }
        AFg1gSDK.i$default(AFLogger.INSTANCE, AFg1cSDK.APP_SET_ID, "App Set Id was collected, but will not be included in the payload.To prevent collection entirely, call disableAppSetId() before initializing the SDK.", false, 4, null);
        int i2 = d + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION;
        w = i2 % 128;
        if (i2 % 2 != 0) {
            throw null;
        }
    }

    private void afInfoLog(@NotNull Map<String, Object> map) {
        d = (w + 11) % 128;
        Intrinsics.checkNotNullParameter(map, "");
        if (this.component4.getMediationNetwork("is_stop_tracking_used")) {
            map.put("istu", String.valueOf(this.component4.getMediationNetwork("is_stop_tracking_used", false)));
        }
        d = (w + 87) % 128;
    }

    private void areAllFieldsValid(@NotNull Map<String, Object> map) throws NumberFormatException {
        w = (d + 59) % 128;
        Intrinsics.checkNotNullParameter(map, "");
        AFf1gSDK.getRevenue(map, this.component3);
        int i = d + 85;
        w = i % 128;
        if (i % 2 != 0) {
            throw null;
        }
    }

    private static long component1() {
        w = (d + 11) % 128;
        long jCurrentTimeMillis = System.currentTimeMillis() - SystemClock.elapsedRealtime();
        int i = w + 67;
        d = i % 128;
        if (i % 2 != 0) {
            return jCurrentTimeMillis;
        }
        throw null;
    }

    private String component2() {
        int i = d + 119;
        w = i % 128;
        if (i % 2 != 0) {
            ((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getString(AppsFlyerProperties.AF_STORE_FROM_API);
            throw null;
        }
        String string = ((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getString(AppsFlyerProperties.AF_STORE_FROM_API);
        if (string == null) {
            string = AFAdRevenueData("AF_STORE");
        }
        int i2 = d + 11;
        w = i2 % 128;
        if (i2 % 2 == 0) {
            return string;
        }
        throw null;
    }

    @NotNull
    private static String component3() {
        StatFs statFs = new StatFs(Environment.getDataDirectory().getAbsolutePath());
        long blockSizeLong = statFs.getBlockSizeLong();
        long availableBlocksLong = statFs.getAvailableBlocksLong() * blockSizeLong;
        long blockCountLong = statFs.getBlockCountLong() * blockSizeLong;
        double dPow = Math.pow(2.0d, 20.0d);
        String str = ((long) (availableBlocksLong / dPow)) + "/" + ((long) (blockCountLong / dPow));
        w = (d + 67) % 128;
        return str;
    }

    private String component4() throws NoSuchAlgorithmException, PackageManager.NameNotFoundException, CertificateException {
        w = (d + 65) % 128;
        String strN_ = AFj1iSDK.N_(this.getMonetizationNetwork.getApplicationContext().getPackageManager(), this.getMonetizationNetwork.getApplicationContext().getPackageName());
        int i = w + 19;
        d = i % 128;
        if (i % 2 != 0) {
            return strN_;
        }
        throw null;
    }

    private String copy() {
        w = (d + 21) % 128;
        String string = ((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getString("preInstallName");
        if (string != null) {
            int i = w + 77;
            d = i % 128;
            if (i % 2 != 0) {
                return string;
            }
            throw null;
        }
        if (this.component4.getMediationNetwork("preInstallName")) {
            d = (w + 91) % 128;
            string = this.component4.AFAdRevenueData("preInstallName", (String) null);
        } else {
            if (copydefault() && (string = (String) getMediationNetwork(new Object[]{this}, -1713193940, 1713193943, System.identityHashCode(this))) == null) {
                int i2 = w + 119;
                d = i2 % 128;
                if (i2 % 2 == 0) {
                    AFAdRevenueData("AF_PRE_INSTALL_NAME");
                    throw null;
                }
                string = AFAdRevenueData("AF_PRE_INSTALL_NAME");
            }
            if (string != null) {
                this.component4.getMediationNetwork("preInstallName", string);
            }
        }
        if (string != null) {
            ((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).set("preInstallName", string);
        }
        return string;
    }

    private boolean copydefault() {
        int i = w + 93;
        d = i % 128;
        if (i % 2 != 0 ? this.component3.getMonetizationNetwork.AFAdRevenueData("appsFlyerCount", 0) > 1 : this.component3.getMonetizationNetwork.AFAdRevenueData("appsFlyerCount", 1) > 1) {
            return false;
        }
        d = (w + 91) % 128;
        return true;
    }

    private void d(@NotNull Map<String, Object> map) {
        d = (w + 13) % 128;
        Intrinsics.checkNotNullParameter(map, "");
        String revenue = AFb1iSDK.getRevenue(this.component3.getMonetizationNetwork);
        if (revenue != null) {
            int i = d + 13;
            w = i % 128;
            if (i % 2 != 0) {
                map.put("uid", revenue);
                boolean mediationNetwork = this.component3.getMonetizationNetwork.getMediationNetwork("CUSTOM_INSTALL_ID_APPLIED", true);
                Intrinsics.checkNotNullExpressionValue(Boolean.valueOf(mediationNetwork), "");
                if (!mediationNetwork) {
                    return;
                }
            } else {
                map.put("uid", revenue);
                boolean mediationNetwork2 = this.component3.getMonetizationNetwork.getMediationNetwork("CUSTOM_INSTALL_ID_APPLIED", false);
                Intrinsics.checkNotNullExpressionValue(Boolean.valueOf(mediationNetwork2), "");
                if (!mediationNetwork2) {
                    return;
                }
            }
            int i2 = w + 117;
            d = i2 % 128;
            if (i2 % 2 != 0) {
                map.put("custom_install_id", Boolean.TRUE);
            } else {
                map.put("custom_install_id", Boolean.TRUE);
                throw null;
            }
        }
    }

    private void e(@NotNull Map<String, Object> map) {
        Intrinsics.checkNotNullParameter(map, "");
        boolean monetizationNetwork = AFg1ySDK.getMonetizationNetwork(this.getMonetizationNetwork);
        AFLogger.afDebugLog("didConfigureTokenRefreshService=" + monetizationNetwork);
        if (!monetizationNetwork) {
            d = (w + 55) % 128;
            map.put("tokenRefreshConfigured", Boolean.FALSE);
            w = (d + 125) % 128;
        }
        map.put("registeredUninstall", Boolean.valueOf(AFg1ySDK.getMonetizationNetwork(this.component4)));
    }

    private boolean equals() {
        d = (w + 89) % 128;
        boolean z = Boolean.parseBoolean(this.component4.AFAdRevenueData("sentSuccessfully", (String) null));
        int i = d + 49;
        w = i % 128;
        if (i % 2 == 0) {
            return z;
        }
        throw null;
    }

    private void force(@NotNull Map<String, Object> map) {
        d = (w + ContentType.LIVE) % 128;
        Intrinsics.checkNotNullParameter(map, "");
        String mediationNetwork = this.equals.getMediationNetwork();
        if (mediationNetwork != null) {
            int i = w + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION;
            d = i % 128;
            if (i % 2 == 0) {
                mediationNetwork.length();
                throw null;
            }
            if (mediationNetwork.length() == 0) {
                return;
            }
            int i2 = d + 41;
            w = i2 % 128;
            if (i2 % 2 == 0) {
                map.put("appsflyerKey", mediationNetwork);
            } else {
                map.put("appsflyerKey", mediationNetwork);
                throw null;
            }
        }
    }

    private static /* synthetic */ Object getCurrencyIso4217Code(Object[] objArr) {
        String[] strArr;
        AFg1oSDK aFg1oSDK = (AFg1oSDK) objArr[0];
        Map map = (Map) objArr[1];
        int i = d + 51;
        w = i % 128;
        if (i % 2 != 0) {
            Intrinsics.checkNotNullParameter(map, "");
            ((AppsFlyerProperties) getMediationNetwork(new Object[]{aFg1oSDK}, 2080605438, -2080605426, System.identityHashCode(aFg1oSDK))).getString(AppsFlyerProperties.APP_ID);
            throw null;
        }
        Intrinsics.checkNotNullParameter(map, "");
        String string = ((AppsFlyerProperties) getMediationNetwork(new Object[]{aFg1oSDK}, 2080605438, -2080605426, System.identityHashCode(aFg1oSDK))).getString(AppsFlyerProperties.APP_ID);
        if (string != null) {
            w = (d + 31) % 128;
            map.put(AppsFlyerProperties.APP_ID, string);
        }
        String string2 = ((AppsFlyerProperties) getMediationNetwork(new Object[]{aFg1oSDK}, 2080605438, -2080605426, System.identityHashCode(aFg1oSDK))).getString(AppsFlyerProperties.CURRENCY_CODE);
        if (string2 != null) {
            if (string2.length() != 3) {
                StringBuilder sb = new StringBuilder("WARNING: currency code should be 3 characters!!! '");
                sb.append(string2);
                sb.append("' is not a legal value.");
                String string3 = sb.toString();
                Intrinsics.checkNotNullExpressionValue(string3, "");
                AFLogger.afWarnLog(string3);
            }
            map.put("currency", string2);
        }
        String string4 = ((AppsFlyerProperties) getMediationNetwork(new Object[]{aFg1oSDK}, 2080605438, -2080605426, System.identityHashCode(aFg1oSDK))).getString(AppsFlyerProperties.IS_UPDATE);
        if (string4 != null) {
            map.put("isUpdate", string4);
        }
        String string5 = ((AppsFlyerProperties) getMediationNetwork(new Object[]{aFg1oSDK}, 2080605438, -2080605426, System.identityHashCode(aFg1oSDK))).getString(AppsFlyerProperties.ADDITIONAL_CUSTOM_DATA);
        if (string5 != null) {
            int i2 = w + 5;
            d = i2 % 128;
            if (i2 % 2 == 0) {
                map.put("customData", string5);
                throw null;
            }
            map.put("customData", string5);
        }
        String string6 = ((AppsFlyerProperties) getMediationNetwork(new Object[]{aFg1oSDK}, 2080605438, -2080605426, System.identityHashCode(aFg1oSDK))).getString(AppsFlyerProperties.APP_USER_ID);
        if (string6 != null) {
            int i3 = w + 69;
            d = i3 % 128;
            if (i3 % 2 == 0) {
                map.put("appUserId", string6);
                throw null;
            }
            map.put("appUserId", string6);
        }
        String string7 = ((AppsFlyerProperties) getMediationNetwork(new Object[]{aFg1oSDK}, 2080605438, -2080605426, System.identityHashCode(aFg1oSDK))).getString(AppsFlyerProperties.USER_EMAILS);
        if (string7 != null) {
            map.put("user_emails", string7);
        }
        AFb1uSDK aFb1uSDK = aFg1oSDK.copy.getRevenue;
        if (aFb1uSDK != null && (strArr = aFb1uSDK.getMediationNetwork) != null) {
            w = (d + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED) % 128;
            map.put("sharing_filter", strArr);
        }
        return null;
    }

    public static /* synthetic */ Object getMediationNetwork(Object[] objArr, int i, int i2, int i3) throws PackageManager.NameNotFoundException {
        int i4 = ~i3;
        int i5 = ((i2 | i3) * 521) + (((~(i4 | i2)) | i) * (-1042)) + (i2 * (-520)) + (i * 522);
        int i6 = ~i;
        switch ((((~(i | i4 | i2)) | (~(i3 | i6)) | (~((~i2) | i6))) * 521) + i5) {
            case 1:
                File file = (File) objArr[0];
                int i7 = d;
                w = (i7 + 43) % 128;
                if (file != null) {
                    w = (i7 + 95) % 128;
                    if (file.exists()) {
                        return Boolean.FALSE;
                    }
                }
                return Boolean.TRUE;
            case 2:
                PackageManager packageManager = (PackageManager) objArr[0];
                String str = (String) objArr[1];
                d = (w + 91) % 128;
                if (Build.VERSION.SDK_INT < 33) {
                    PackageInfo packageInfo = packageManager.getPackageInfo(str, 0);
                    Intrinsics.checkNotNullExpressionValue(packageInfo, "");
                    return packageInfo;
                }
                PackageInfo packageInfo2 = packageManager.getPackageInfo(str, PackageManager.PackageInfoFlags.of(0L));
                Intrinsics.checkNotNullExpressionValue(packageInfo2, "");
                w = (d + 21) % 128;
                return packageInfo2;
            case 3:
                AFg1oSDK aFg1oSDK = (AFg1oSDK) objArr[0];
                File currencyIso4217Code = getCurrencyIso4217Code(getMediationNetwork("ro.appsflyer.preinstall.path"));
                if (getMediationNetwork(currencyIso4217Code)) {
                    currencyIso4217Code = getCurrencyIso4217Code(aFg1oSDK.AFAdRevenueData("AF_PRE_INSTALL_PATH"));
                }
                if (getMediationNetwork(currencyIso4217Code)) {
                    d = (w + 1) % 128;
                    currencyIso4217Code = getCurrencyIso4217Code("/data/local/tmp/pre_install.appsflyer");
                    d = (w + 79) % 128;
                }
                if (getMediationNetwork(currencyIso4217Code)) {
                    currencyIso4217Code = getCurrencyIso4217Code("/etc/pre_install.appsflyer");
                }
                if (!getMediationNetwork(currencyIso4217Code)) {
                    String packageName = aFg1oSDK.getMonetizationNetwork.getPackageName();
                    Intrinsics.checkNotNullExpressionValue(packageName, "");
                    String str2 = (String) getMediationNetwork(new Object[]{currencyIso4217Code, packageName}, -2094417185, 2094417192, (int) System.currentTimeMillis());
                    d = (w + 89) % 128;
                    return str2;
                }
                return null;
            case 4:
                return AFAdRevenueData(objArr);
            case 5:
                return getCurrencyIso4217Code(objArr);
            case 6:
                return getMonetizationNetwork(objArr);
            case 7:
                return getRevenue(objArr);
            case 8:
                AFg1oSDK aFg1oSDK2 = (AFg1oSDK) objArr[0];
                Map map = (Map) objArr[1];
                w = (d + 115) % 128;
                Intrinsics.checkNotNullParameter(map, "");
                AFb1mSDK aFb1mSDKK_ = AFb1jSDK.k_(aFg1oSDK2.getMonetizationNetwork.getContentResolver());
                if (aFb1mSDKK_ != null) {
                    w = (d + 15) % 128;
                    map.put("amazon_aid", aFb1mSDKK_.getMonetizationNetwork);
                    map.put("amazon_aid_limit", String.valueOf(aFb1mSDKK_.getMediationNetwork));
                    return null;
                }
                return null;
            case 9:
                return component1(objArr);
            case 10:
                d = (w + 13) % 128;
                long jCurrentTimeMillis = System.currentTimeMillis();
                w = (d + 7) % 128;
                return Long.valueOf(jCurrentTimeMillis);
            case 11:
                return areAllFieldsValid(objArr);
            case 12:
                AFg1oSDK aFg1oSDK3 = (AFg1oSDK) objArr[0];
                w = (d + 59) % 128;
                AppsFlyerProperties appsFlyerProperties = (AppsFlyerProperties) aFg1oSDK3.copydefault.getValue();
                d = (w + 23) % 128;
                return appsFlyerProperties;
            default:
                return getMediationNetwork(objArr);
        }
    }

    private final SimpleDateFormat getMonetizationNetwork() {
        d = (w + 93) % 128;
        SimpleDateFormat simpleDateFormat = (SimpleDateFormat) this.AFLogger.getValue();
        int i = d + 91;
        w = i % 128;
        if (i % 2 == 0) {
            return simpleDateFormat;
        }
        throw null;
    }

    private final void hashCode(Map<String, Object> map) {
        int i = d + 49;
        w = i % 128;
        if (i % 2 != 0) {
            int i2 = 74 / 0;
            if (!AFg1kSDK.getMediationNetwork(this.getMonetizationNetwork)) {
                return;
            }
        } else if (!AFg1kSDK.getMediationNetwork(this.getMonetizationNetwork)) {
            return;
        }
        map.put("inst_app", Boolean.TRUE);
        w = (d + 85) % 128;
    }

    private void i(@NotNull Map<String, Object> map) throws PackageManager.NameNotFoundException {
        getMediationNetwork(new Object[]{this, map}, -1753918152, 1753918160, System.identityHashCode(this));
    }

    private void registerClient(@NotNull Map<String, Object> map) {
        Intrinsics.checkNotNullParameter(map, "");
        long j = this.areAllFieldsValid.toString;
        if (j != 0) {
            int i = w + 97;
            d = i % 128;
            if (i % 2 == 0) {
                map.put("prev_session_dur", Long.valueOf(j));
                throw null;
            }
            map.put("prev_session_dur", Long.valueOf(j));
        }
        w = (d + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED) % 128;
    }

    private static PackageInfo s_(PackageManager packageManager, String str) {
        return (PackageInfo) getMediationNetwork(new Object[]{packageManager, str}, 1014234820, -1014234818, (int) System.currentTimeMillis());
    }

    private final void toString(Map<String, Object> map) {
        d = (w + 33) % 128;
        if (((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).isOtherSdkStringDisabled()) {
            return;
        }
        d = (w + 69) % 128;
        map.put("batteryLevel", String.valueOf(this.getMediationNetwork.getRevenue(this.getMonetizationNetwork).getRevenue));
        w = (d + 103) % 128;
    }

    private void unregisterClient(@NotNull Map<String, Object> map) {
        int i = d + 27;
        w = i % 128;
        if (i % 2 == 0) {
            Intrinsics.checkNotNullParameter(map, "");
            map.put("af_preinstalled", String.valueOf(AFc1pSDK.AFAdRevenueData(this.getMonetizationNetwork)));
        } else {
            Intrinsics.checkNotNullParameter(map, "");
            map.put("af_preinstalled", String.valueOf(AFc1pSDK.AFAdRevenueData(this.getMonetizationNetwork)));
            throw null;
        }
    }

    private static void w(@NotNull Map<String, Object> map) {
        Intrinsics.checkNotNullParameter(map, "");
        try {
            map.put("lang", Locale.getDefault().getDisplayLanguage());
            d = (w + 103) % 128;
        } catch (Exception e) {
            AFLogger.afErrorLog("Exception while collecting display language name. ", e);
        }
        try {
            map.put("lang_code", Locale.getDefault().getLanguage());
            w = (d + 119) % 128;
        } catch (Exception e2) {
            AFLogger.afErrorLog("Exception while collecting display language code. ", e2);
        }
        try {
            map.put(AdRevenueScheme.COUNTRY, Locale.getDefault().getCountry());
            d = (w + 103) % 128;
        } catch (Exception e3) {
            AFLogger.afErrorLog("Exception while collecting country name. ", e3);
        }
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final void getRevenue(@NotNull AFh1rSDK aFh1rSDK) throws PackageManager.NameNotFoundException, UnsupportedEncodingException {
        w = (d + 35) % 128;
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        Map<String, Object> map = aFh1rSDK.AFAdRevenueData;
        Intrinsics.checkNotNullExpressionValue(map, "");
        getCurrencyIso4217Code(map, aFh1rSDK.getMediationNetwork());
        component2(map);
        w(map);
        getMediationNetwork(new Object[]{this, map}, -1412383531, 1412383531, System.identityHashCode(this));
        getCurrencyIso4217Code(map, this.copy.AFAdRevenueData);
        getMediationNetwork(new Object[]{this, map}, -1753918152, 1753918160, System.identityHashCode(this));
        map.put("cell", V.f(new Pair("mcc", Integer.valueOf(this.getMonetizationNetwork.getResources().getConfiguration().mcc)), new Pair("mnc", Integer.valueOf(this.getMonetizationNetwork.getResources().getConfiguration().mnc))));
        map.put("sig", component4());
        map.put("last_boot_time", Long.valueOf(component1()));
        map.put("disk", component3());
        int i = w + 25;
        d = i % 128;
        if (i % 2 == 0) {
            throw null;
        }
    }

    private void component1(@NotNull Map<String, ? extends Object> map) {
        Intrinsics.checkNotNullParameter(map, "");
        AFh1vSDK aFh1vSDK = this.areAllFieldsValid;
        HashMap map2 = new HashMap(aFh1vSDK.getRevenue);
        aFh1vSDK.getRevenue.clear();
        this.areAllFieldsValid.getCurrencyIso4217Code.getMonetizationNetwork("gcd");
        Intrinsics.checkNotNullExpressionValue(map2, "");
        if (map2.isEmpty()) {
            d = (w + ContentType.LIVE) % 128;
            return;
        }
        w = (d + 71) % 128;
        Map<String, Object> revenue = AFa1tSDK.getRevenue(map);
        Intrinsics.checkNotNullExpressionValue(revenue, "");
        revenue.put("gcd", map2);
    }

    private final void component4(Map<String, Object> map) {
        AFg1uSDK.AFa1uSDK revenue = this.getMediationNetwork.getRevenue(this.getMonetizationNetwork);
        float f = revenue.getRevenue;
        String str = revenue.getMediationNetwork;
        map.put("btl", String.valueOf(f));
        if (str != null) {
            w = (d + 67) % 128;
            map.put("btch", str);
            w = (d + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION) % 128;
        }
    }

    private void equals(@NotNull Map<String, Object> map) {
        int i = w + 101;
        d = i % 128;
        if (i % 2 == 0) {
            Intrinsics.checkNotNullParameter(map, "");
            map.put("is_pc", Boolean.valueOf(this.getMonetizationNetwork.getApplicationContext().getPackageManager().hasSystemFeature("com.google.android.play.feature.HPE_EXPERIENCE")));
            throw null;
        }
        Intrinsics.checkNotNullParameter(map, "");
        map.put("is_pc", Boolean.valueOf(this.getMonetizationNetwork.getApplicationContext().getPackageManager().hasSystemFeature("com.google.android.play.feature.HPE_EXPERIENCE")));
        int i2 = w + 99;
        d = i2 % 128;
        if (i2 % 2 == 0) {
            throw null;
        }
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final void getMonetizationNetwork(@NotNull AFh1rSDK aFh1rSDK) throws JSONException, PackageManager.NameNotFoundException, NumberFormatException {
        w = (d + 53) % 128;
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        Map<String, Object> map = aFh1rSDK.AFAdRevenueData;
        if (aFh1rSDK.getMediationNetwork()) {
            String str = aFh1rSDK.component3;
            AFc1kSDK aFc1kSDK = this.copy;
            getMonetizationNetwork(aFh1rSDK, str, aFc1kSDK.getMediationNetwork, aFc1kSDK.getMonetizationNetwork);
            w = (d + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED) % 128;
        } else if (!(aFh1rSDK instanceof AFh1hSDK)) {
            int i = d + 7;
            w = i % 128;
            if (i % 2 != 0) {
                Intrinsics.checkNotNullExpressionValue(map, "");
                String str2 = aFh1rSDK.areAllFieldsValid;
                Intrinsics.checkNotNullExpressionValue(str2, "");
                getMediationNetwork(map, str2);
                int i2 = 48 / 0;
            } else {
                Intrinsics.checkNotNullExpressionValue(map, "");
                String str3 = aFh1rSDK.areAllFieldsValid;
                Intrinsics.checkNotNullExpressionValue(str3, "");
                getMediationNetwork(map, str3);
            }
        }
        if (B.j(AFe1mSDK.CONVERSION, AFe1mSDK.LAUNCH, AFe1mSDK.INAPP).contains(aFh1rSDK.getCurrencyIso4217Code())) {
            d = (w + 103) % 128;
            Intrinsics.checkNotNullExpressionValue(map, "");
            equals(map);
        }
        if (aFh1rSDK.getRevenue()) {
            d = (w + 15) % 128;
            Intrinsics.checkNotNullExpressionValue(map, "");
            areAllFieldsValid(map);
        }
        Intrinsics.checkNotNullExpressionValue(map, "");
        force(map);
        AFInAppEventType(map);
        getMediationNetwork(new Object[]{this, map}, -140518465, 140518471, System.identityHashCode(this));
        AFKeystoreWrapper(map);
        d(map);
        getMediationNetwork(map, aFh1rSDK.getMediationNetwork());
        e(map);
        afInfoLog(map);
        getRevenue(map, aFh1rSDK);
        map.put("af_events_api", "1");
    }

    private String areAllFieldsValid() {
        String strComponent2 = null;
        if (!(!this.component4.getMediationNetwork("INSTALL_STORE"))) {
            return this.component4.AFAdRevenueData("INSTALL_STORE", (String) null);
        }
        if (copydefault()) {
            int i = d + ContentType.USER_GENERATED_LIVE;
            w = i % 128;
            if (i % 2 == 0) {
                strComponent2 = component2();
            } else {
                component2();
                throw null;
            }
        } else {
            d = (w + 67) % 128;
        }
        this.component4.getMediationNetwork("INSTALL_STORE", strComponent2);
        return strComponent2;
    }

    private static void component2(@NotNull Map<String, Object> map) throws UnsupportedEncodingException {
        d = (w + 37) % 128;
        Intrinsics.checkNotNullParameter(map, "");
        Object[] objArr = new Object[1];
        a("\u008f\u0089\u0087\u0083\u008e", null, null, 127 - ExpandableListView.getPackedPositionType(0L), objArr);
        map.put(((String) objArr[0]).intern(), Build.BRAND);
        map.put("device", Build.DEVICE);
        map.put("product", Build.PRODUCT);
        map.put("sdk", String.valueOf(Build.VERSION.SDK_INT));
        map.put(DtbDeviceData.DEVICE_DATA_MODEL_KEY, Build.MODEL);
        map.put("deviceType", Build.TYPE);
        int i = w + 95;
        d = i % 128;
        if (i % 2 == 0) {
            throw null;
        }
    }

    private final void copydefault(Map<String, Object> map) {
        w = (d + 33) % 128;
        int i = w + 97;
        d = i % 128;
        if (i % 2 != 0) {
            UiModeManager uiModeManager = (UiModeManager) this.getMonetizationNetwork.getSystemService(UiModeManager.class);
            if (uiModeManager == null || uiModeManager.getCurrentModeType() != 4) {
                return;
            }
            map.put("tv", Boolean.TRUE);
            return;
        }
        throw null;
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x006f A[PHI: r0 r1
  0x006f: PHI (r0v7 java.lang.String) = (r0v6 java.lang.String), (r0v12 java.lang.String) binds: [B:8:0x006d, B:5:0x0043] A[DONT_GENERATE, DONT_INLINE]
  0x006f: PHI (r1v3 java.lang.String) = (r1v2 java.lang.String), (r1v5 java.lang.String) binds: [B:8:0x006d, B:5:0x0043] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void component3(@org.jetbrains.annotations.NotNull java.util.Map<java.lang.String, java.lang.Object> r7) {
        /*
            r6 = this;
            int r0 = com.appsflyer.internal.AFg1oSDK.w
            int r0 = r0 + 63
            int r1 = r0 % 128
            com.appsflyer.internal.AFg1oSDK.d = r1
            int r0 = r0 % 2
            java.lang.String r1 = "onelinkVersion"
            java.lang.String r2 = "oneLinkSlug"
            r3 = -2080605426(0xffffffff83fc7b0e, float:-1.4839481E-36)
            r4 = 2080605438(0x7c0384fe, float:2.7315532E36)
            java.lang.String r5 = ""
            if (r0 != 0) goto L46
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r5)
            java.lang.Object[] r0 = new java.lang.Object[]{r6}
            int r5 = java.lang.System.identityHashCode(r6)
            java.lang.Object r0 = getMediationNetwork(r0, r4, r3, r5)
            com.appsflyer.AppsFlyerProperties r0 = (com.appsflyer.AppsFlyerProperties) r0
            java.lang.String r0 = r0.getString(r2)
            java.lang.Object[] r2 = new java.lang.Object[]{r6}
            int r5 = java.lang.System.identityHashCode(r6)
            java.lang.Object r2 = getMediationNetwork(r2, r4, r3, r5)
            com.appsflyer.AppsFlyerProperties r2 = (com.appsflyer.AppsFlyerProperties) r2
            java.lang.String r1 = r2.getString(r1)
            r2 = 69
            int r2 = r2 / 0
            if (r0 == 0) goto L7c
            goto L6f
        L46:
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r5)
            java.lang.Object[] r0 = new java.lang.Object[]{r6}
            int r5 = java.lang.System.identityHashCode(r6)
            java.lang.Object r0 = getMediationNetwork(r0, r4, r3, r5)
            com.appsflyer.AppsFlyerProperties r0 = (com.appsflyer.AppsFlyerProperties) r0
            java.lang.String r0 = r0.getString(r2)
            java.lang.Object[] r2 = new java.lang.Object[]{r6}
            int r5 = java.lang.System.identityHashCode(r6)
            java.lang.Object r2 = getMediationNetwork(r2, r4, r3, r5)
            com.appsflyer.AppsFlyerProperties r2 = (com.appsflyer.AppsFlyerProperties) r2
            java.lang.String r1 = r2.getString(r1)
            if (r0 == 0) goto L7c
        L6f:
            int r2 = com.appsflyer.internal.AFg1oSDK.w
            int r2 = r2 + 121
            int r2 = r2 % 128
            com.appsflyer.internal.AFg1oSDK.d = r2
            java.lang.String r2 = "onelink_id"
            r7.put(r2, r0)
        L7c:
            if (r1 == 0) goto L83
            java.lang.String r0 = "onelink_ver"
            r7.put(r0, r1)
        L83:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFg1oSDK.component3(java.util.Map):void");
    }

    private final boolean AFKeystoreWrapper() {
        if (!((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getBoolean(AppsFlyerProperties.COLLECT_ANDROID_ID_FORCE_BY_USER, false)) {
            int i = w + 23;
            d = i % 128;
            if (i % 2 != 0 ? !((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getBoolean(AppsFlyerProperties.COLLECT_IMEI_FORCE_BY_USER, false) : !((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getBoolean(AppsFlyerProperties.COLLECT_IMEI_FORCE_BY_USER, false)) {
                return !AFa1tSDK.getCurrencyIso4217Code(this.getMonetizationNetwork);
            }
        }
        w = (d + 115) % 128;
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0048  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void AFInAppEventParameterName(@org.jetbrains.annotations.NotNull java.util.Map<java.lang.String, java.lang.Object> r7) {
        /*
            r6 = this;
            java.lang.String r0 = ""
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            com.appsflyer.internal.AFc1pSDK r1 = r6.component3
            java.lang.String r1 = r1.component2()
            com.appsflyer.internal.AFc1qSDK r2 = r6.component4
            java.lang.Object[] r2 = new java.lang.Object[]{r2, r1}
            long r3 = java.lang.System.currentTimeMillis()
            int r3 = (int) r3
            r4 = 381318279(0x16ba7487, float:3.012346E-25)
            r5 = -381318268(0xffffffffe9458b84, float:-1.4926077E25)
            java.lang.Object r2 = getMediationNetwork(r2, r4, r5, r3)
            java.lang.String r2 = (java.lang.String) r2
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L2e
            boolean r5 = r2.equals(r1)
            if (r5 != 0) goto L2e
            r5 = r4
            goto L2f
        L2e:
            r5 = r3
        L2f:
            if (r2 != 0) goto L3c
            int r2 = com.appsflyer.internal.AFg1oSDK.w
            int r2 = r2 + 67
            int r2 = r2 % 128
            com.appsflyer.internal.AFg1oSDK.d = r2
            if (r1 == 0) goto L3c
            r3 = r4
        L3c:
            if (r5 != 0) goto L48
            int r2 = com.appsflyer.internal.AFg1oSDK.w
            int r2 = r2 + 9
            int r2 = r2 % 128
            com.appsflyer.internal.AFg1oSDK.d = r2
            if (r3 == 0) goto L4d
        L48:
            java.lang.String r2 = "af_latestchannel"
            r7.put(r2, r1)
        L4d:
            java.lang.String r1 = r6.areAllFieldsValid()
            if (r1 == 0) goto L86
            int r2 = com.appsflyer.internal.AFg1oSDK.w
            int r2 = r2 + 101
            int r3 = r2 % 128
            com.appsflyer.internal.AFg1oSDK.d = r3
            int r2 = r2 % 2
            java.lang.String r3 = "af_installstore"
            if (r2 == 0) goto L73
            java.util.Locale r2 = java.util.Locale.getDefault()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r0)
            java.lang.String r1 = r1.toLowerCase(r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r0)
            r7.put(r3, r1)
            goto L86
        L73:
            java.util.Locale r2 = java.util.Locale.getDefault()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r0)
            java.lang.String r1 = r1.toLowerCase(r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r0)
            r7.put(r3, r1)
            r7 = 0
            throw r7
        L86:
            java.lang.String r1 = r6.copy()
            if (r1 == 0) goto L9f
            java.util.Locale r2 = java.util.Locale.getDefault()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r0)
            java.lang.String r1 = r1.toLowerCase(r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r0)
            java.lang.String r2 = "af_preinstall_name"
            r7.put(r2, r1)
        L9f:
            java.lang.String r1 = r6.component2()
            if (r1 == 0) goto Lb8
            java.util.Locale r2 = java.util.Locale.getDefault()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r0)
            java.lang.String r1 = r1.toLowerCase(r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r0)
            java.lang.String r0 = "af_currentstore"
            r7.put(r0, r1)
        Lb8:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFg1oSDK.AFInAppEventParameterName(java.util.Map):void");
    }

    private static /* synthetic */ Object areAllFieldsValid(Object[] objArr) {
        AFc1qSDK aFc1qSDK = (AFc1qSDK) objArr[0];
        String str = (String) objArr[1];
        w = (d + 1) % 128;
        String strAFAdRevenueData = aFc1qSDK.AFAdRevenueData("CACHED_CHANNEL", (String) null);
        if (strAFAdRevenueData != null) {
            int i = d + 27;
            w = i % 128;
            if (i % 2 == 0) {
                return strAFAdRevenueData;
            }
            throw null;
        }
        aFc1qSDK.getMediationNetwork("CACHED_CHANNEL", str);
        d = (w + 19) % 128;
        return str;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0034  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static /* synthetic */ java.lang.Object component1(java.lang.Object[] r8) {
        /*
            r0 = 0
            r1 = r8[r0]
            com.appsflyer.internal.AFg1oSDK r1 = (com.appsflyer.internal.AFg1oSDK) r1
            r2 = 1
            r2 = r8[r2]
            java.util.Map r2 = (java.util.Map) r2
            r3 = 2
            r8 = r8[r3]
            java.lang.String r8 = (java.lang.String) r8
            java.lang.String r4 = ""
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r4)
            java.lang.String r4 = "referrer"
            if (r8 == 0) goto L3f
            int r5 = com.appsflyer.internal.AFg1oSDK.w
            int r5 = r5 + 53
            int r6 = r5 % 128
            com.appsflyer.internal.AFg1oSDK.d = r6
            int r5 = r5 % r3
            if (r5 != 0) goto L2d
            int r5 = r8.length()
            r6 = 87
            int r6 = r6 / r0
            if (r5 != 0) goto L34
            goto L3f
        L2d:
            int r0 = r8.length()
            if (r0 != 0) goto L34
            goto L3f
        L34:
            r2.put(r4, r8)
            int r8 = com.appsflyer.internal.AFg1oSDK.w
            int r8 = r8 + 103
            int r8 = r8 % 128
            com.appsflyer.internal.AFg1oSDK.d = r8
        L3f:
            com.appsflyer.internal.AFc1qSDK r8 = r1.component4
            java.lang.String r0 = "extraReferrers"
            r5 = 0
            java.lang.String r8 = r8.AFAdRevenueData(r0, r5)
            if (r8 == 0) goto L4d
            r2.put(r0, r8)
        L4d:
            java.lang.Object[] r8 = new java.lang.Object[]{r1}
            int r0 = java.lang.System.identityHashCode(r1)
            r6 = 2080605438(0x7c0384fe, float:2.7315532E36)
            r7 = -2080605426(0xffffffff83fc7b0e, float:-1.4839481E-36)
            java.lang.Object r8 = getMediationNetwork(r8, r6, r7, r0)
            com.appsflyer.AppsFlyerProperties r8 = (com.appsflyer.AppsFlyerProperties) r8
            com.appsflyer.internal.AFc1qSDK r0 = r1.component4
            java.lang.String r8 = r8.getReferrer(r0)
            if (r8 == 0) goto L81
            int r0 = r8.length()
            if (r0 != 0) goto L70
            goto L81
        L70:
            java.lang.Object r0 = r2.get(r4)
            if (r0 != 0) goto L81
            int r0 = com.appsflyer.internal.AFg1oSDK.w
            int r0 = r0 + 33
            int r0 = r0 % 128
            com.appsflyer.internal.AFg1oSDK.d = r0
            r2.put(r4, r8)
        L81:
            int r8 = com.appsflyer.internal.AFg1oSDK.d
            int r8 = r8 + 15
            int r0 = r8 % 128
            com.appsflyer.internal.AFg1oSDK.w = r0
            int r8 = r8 % r3
            if (r8 != 0) goto L8d
            return r5
        L8d:
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFg1oSDK.component1(java.lang.Object[]):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0041 A[PHI: r0 r5
  0x0041: PHI (r0v5 long) = (r0v4 long), (r0v11 long) binds: [B:8:0x003f, B:5:0x0026] A[DONT_GENERATE, DONT_INLINE]
  0x0041: PHI (r5v1 long) = (r5v0 long), (r5v3 long) binds: [B:8:0x003f, B:5:0x0026] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void copy(@org.jetbrains.annotations.NotNull java.util.Map<java.lang.String, java.lang.Object> r9) {
        /*
            r8 = this;
            int r0 = com.appsflyer.internal.AFg1oSDK.d
            int r0 = r0 + 97
            int r1 = r0 % 128
            com.appsflyer.internal.AFg1oSDK.w = r1
            int r0 = r0 % 2
            java.lang.String r1 = ""
            java.lang.String r2 = "AppsFlyerTimePassedSincePrevLaunch"
            if (r0 == 0) goto L29
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r1)
            com.appsflyer.internal.AFc1qSDK r0 = r8.component4
            r3 = 1
            long r0 = r0.getCurrencyIso4217Code(r2, r3)
            long r5 = java.lang.System.currentTimeMillis()
            com.appsflyer.internal.AFc1qSDK r7 = r8.component4
            r7.getMonetizationNetwork(r2, r5)
            int r2 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r2 <= 0) goto L51
            goto L41
        L29:
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r1)
            com.appsflyer.internal.AFc1qSDK r0 = r8.component4
            r3 = 0
            long r0 = r0.getCurrencyIso4217Code(r2, r3)
            long r5 = java.lang.System.currentTimeMillis()
            com.appsflyer.internal.AFc1qSDK r7 = r8.component4
            r7.getMonetizationNetwork(r2, r5)
            int r2 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r2 <= 0) goto L51
        L41:
            java.util.concurrent.TimeUnit r2 = java.util.concurrent.TimeUnit.MILLISECONDS
            long r5 = r5 - r0
            long r0 = r2.toSeconds(r5)
            int r2 = com.appsflyer.internal.AFg1oSDK.d
            int r2 = r2 + 81
            int r2 = r2 % 128
            com.appsflyer.internal.AFg1oSDK.w = r2
            goto L53
        L51:
            r0 = -1
        L53:
            java.lang.String r2 = "timepassedsincelastlaunch"
            java.lang.String r0 = java.lang.String.valueOf(r0)
            r9.put(r2, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFg1oSDK.copy(java.util.Map):void");
    }

    private final String AFInAppEventType() {
        return (String) getMediationNetwork(new Object[]{this}, -1713193940, 1713193943, System.identityHashCode(this));
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final void getRevenue(@NotNull Map<String, Object> map, int i, int i2) {
        Intrinsics.checkNotNullParameter(map, "");
        map.put("counter", String.valueOf(i));
        map.put("iaecounter", String.valueOf(i2));
        boolean z = false;
        if (!equals()) {
            int i3 = d + 19;
            w = i3 % 128;
            if (i3 % 2 == 0) {
                z = true;
            }
        }
        map.put("isFirstCall", String.valueOf(z));
        w = (d + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED) % 128;
    }

    private static /* synthetic */ Object getRevenue(Object[] objArr) {
        InputStreamReader inputStreamReader;
        Properties properties;
        File file = (File) objArr[0];
        String str = (String) objArr[1];
        try {
            try {
                if (file == null) {
                    d = (w + 43) % 128;
                    return null;
                }
                try {
                    properties = new Properties();
                    inputStreamReader = new InputStreamReader(new FileInputStream(file), Charset.defaultCharset());
                } catch (FileNotFoundException unused) {
                    inputStreamReader = null;
                } catch (Throwable th) {
                    th = th;
                    inputStreamReader = null;
                }
                try {
                    properties.load(inputStreamReader);
                    AFLogger.afInfoLog("Found PreInstall property!");
                    String property = properties.getProperty(str);
                    try {
                        inputStreamReader.close();
                        return property;
                    } catch (Throwable th2) {
                        AFLogger.afErrorLog(th2.getMessage(), th2);
                        return property;
                    }
                } catch (FileNotFoundException unused2) {
                    AFLogger.afDebugLog("PreInstall file wasn't found: " + file.getAbsolutePath());
                    if (inputStreamReader != null) {
                        inputStreamReader.close();
                        d = (w + 31) % 128;
                    }
                    return null;
                } catch (Throwable th3) {
                    th = th3;
                    AFLogger.afErrorLog(th.getMessage(), th);
                    if (inputStreamReader != null) {
                        inputStreamReader.close();
                    }
                    return null;
                }
            } catch (Throwable th4) {
                AFLogger.afErrorLog(th4.getMessage(), th4);
            }
        } catch (Throwable th5) {
            if (inputStreamReader != null) {
                try {
                    inputStreamReader.close();
                    w = (d + 91) % 128;
                } catch (Throwable th6) {
                    AFLogger.afErrorLog(th6.getMessage(), th6);
                }
            }
            throw th5;
        }
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final Long getCurrencyIso4217Code() {
        int i = w + 43;
        int i2 = i % 128;
        d = i2;
        if (i % 2 != 0) {
            Context context = this.toString.getMonetizationNetwork;
            if (context == null) {
                return null;
            }
            int i3 = i2 + 49;
            w = i3 % 128;
            if (i3 % 2 == 0) {
                PackageManager packageManager = context.getPackageManager();
                if (packageManager != null) {
                    String packageName = context.getPackageName();
                    Intrinsics.checkNotNullExpressionValue(packageName, "");
                    PackageInfo packageInfo = (PackageInfo) getMediationNetwork(new Object[]{packageManager, packageName}, 1014234820, -1014234818, (int) System.currentTimeMillis());
                    if (packageInfo != null) {
                        Long lValueOf = Long.valueOf(packageInfo.firstInstallTime);
                        d = (w + 47) % 128;
                        return lValueOf;
                    }
                }
                int i4 = d + 51;
                w = i4 % 128;
                if (i4 % 2 != 0) {
                    int i5 = 27 / 0;
                }
                return null;
            }
            context.getPackageManager();
            throw null;
        }
        Context context2 = this.toString.getMonetizationNetwork;
        throw null;
    }

    private final void getMonetizationNetwork(Map<String, Object> map) {
        PackageInfo packageInfo;
        int i = w + 41;
        d = i % 128;
        try {
            if (i % 2 == 0) {
                packageInfo = this.getMonetizationNetwork.getPackageManager().getPackageInfo(this.getMonetizationNetwork.getPackageName(), 1);
                if (packageInfo.versionCode > this.component4.AFAdRevenueData("versionCode", 1)) {
                    this.component4.getMediationNetwork("versionCode", packageInfo.versionCode);
                }
            } else {
                packageInfo = this.getMonetizationNetwork.getPackageManager().getPackageInfo(this.getMonetizationNetwork.getPackageName(), 0);
                if (packageInfo.versionCode > this.component4.AFAdRevenueData("versionCode", 0)) {
                    this.component4.getMediationNetwork("versionCode", packageInfo.versionCode);
                }
            }
            map.put("app_version_code", String.valueOf(packageInfo.versionCode));
            Context context = this.component3.getRevenue.getMonetizationNetwork;
            map.put("app_version_name", AFj1iSDK.getMediationNetwork(context, context.getPackageName()));
            map.put("targetSDKver", Integer.valueOf(this.component3.getRevenue.getMonetizationNetwork.getApplicationInfo().targetSdkVersion));
            long j = packageInfo.firstInstallTime;
            long j2 = packageInfo.lastUpdateTime;
            map.put("date1", getMonetizationNetwork().format(new Date(j)));
            map.put("date2", getMonetizationNetwork().format(new Date(j2)));
            Object[] objArr = new Object[1];
            a("\u008d\u0085\u0087\u008c\u008b\u008a\u0089\u0088\u0087\u0086\u0085\u0084\u0083\u0082\u0081", null, null, 127 - TextUtils.getTrimmedLength(""), objArr);
            String strIntern = ((String) objArr[0]).intern();
            SimpleDateFormat monetizationNetwork = getMonetizationNetwork();
            Intrinsics.checkNotNullExpressionValue(monetizationNetwork, "");
            map.put(strIntern, getMediationNetwork(monetizationNetwork));
            w = (d + 47) % 128;
        } catch (Throwable th) {
            AFLogger.afErrorLog("Exception while collecting app version data ", th, true);
        }
    }

    private final String AFAdRevenueData(String str) {
        int i = d + 5;
        w = i % 128;
        if (i % 2 == 0) {
            return this.component3.getCurrencyIso4217Code(str);
        }
        int i2 = 38 / 0;
        return this.component3.getCurrencyIso4217Code(str);
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final void AFAdRevenueData(@NotNull Map<String, Object> map) throws PackageManager.NameNotFoundException {
        getMediationNetwork(new Object[]{this, map}, -1412383531, 1412383531, System.identityHashCode(this));
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final void getMediationNetwork(@NotNull AFh1rSDK aFh1rSDK) {
        d = (w + 11) % 128;
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        Map<String, Object> map = aFh1rSDK.AFAdRevenueData;
        Intrinsics.checkNotNullExpressionValue(map, "");
        getMediationNetwork(map);
        Map<String, Object> map2 = aFh1rSDK.AFAdRevenueData;
        Intrinsics.checkNotNullExpressionValue(map2, "");
        getMonetizationNetwork(map2);
        Map<String, Object> map3 = aFh1rSDK.AFAdRevenueData;
        Intrinsics.checkNotNullExpressionValue(map3, "");
        AFInAppEventParameterName(map3);
        Map<String, Object> map4 = aFh1rSDK.AFAdRevenueData;
        Intrinsics.checkNotNullExpressionValue(map4, "");
        unregisterClient(map4);
        Map<String, Object> map5 = aFh1rSDK.AFAdRevenueData;
        Intrinsics.checkNotNullExpressionValue(map5, "");
        afDebugLog(map5);
        if (getMediationNetwork().contains(aFh1rSDK.getCurrencyIso4217Code())) {
            d = (w + 125) % 128;
            Map<String, Object> map6 = aFh1rSDK.AFAdRevenueData;
            Intrinsics.checkNotNullExpressionValue(map6, "");
            afErrorLog(map6);
            d = (w + 17) % 128;
        }
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final long AFAdRevenueData() {
        return ((Long) getMediationNetwork(new Object[]{this}, 1094427935, -1094427925, System.identityHashCode(this))).longValue();
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final void AFAdRevenueData(@NotNull AFh1rSDK aFh1rSDK) throws PackageManager.NameNotFoundException {
        getMediationNetwork(new Object[]{this, aFh1rSDK}, 840096269, -840096265, System.identityHashCode(this));
    }

    private void getCurrencyIso4217Code(@NotNull Map<String, Object> map, boolean z) {
        Intrinsics.checkNotNullParameter(map, "");
        HashMap map2 = new HashMap();
        map2.put("cpu_abi", getMediationNetwork("ro.product.cpu.abi"));
        map2.put("cpu_abi2", getMediationNetwork("ro.product.cpu.abi2"));
        map2.put("arch", getMediationNetwork("os.arch"));
        map2.put("build_display_id", getMediationNetwork("ro.build.display.id"));
        if (z) {
            w = (d + 13) % 128;
            component4(map2);
            if (this.component3.getMonetizationNetwork.AFAdRevenueData("appsFlyerCount", 0) <= 2) {
                map2.putAll(this.AFAdRevenueData.AFAdRevenueData());
            }
        }
        map2.put("dim", this.component2.AFAdRevenueData(this.getMonetizationNetwork));
        map.put("deviceData", map2);
        d = (w + 1) % 128;
    }

    private static void getRevenue(@NotNull Map<String, Object> map, @NotNull AFh1rSDK aFh1rSDK) {
        Intrinsics.checkNotNullParameter(map, "");
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        String str = aFh1rSDK.areAllFieldsValid;
        if (str != null) {
            map.put("eventName", str);
            Map map2 = aFh1rSDK.getMonetizationNetwork;
            if (map2 == null) {
                map2 = new HashMap();
            }
            map.put("eventValue", new JSONObject(map2).toString());
        }
    }

    private void getRevenue(@NotNull Map<String, Object> map, String str) throws PackageManager.NameNotFoundException {
        getMediationNetwork(new Object[]{this, map, str}, 1763970144, -1763970135, System.identityHashCode(this));
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final void getRevenue(@NotNull Map<String, Object> map) throws PackageManager.NameNotFoundException {
        getMediationNetwork(new Object[]{this, map}, -1435534785, 1435534790, System.identityHashCode(this));
    }

    private final AppsFlyerProperties getRevenue() {
        return (AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this));
    }

    private static List<AFe1mSDK> getMediationNetwork() {
        w = (d + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION) % 128;
        List<AFe1mSDK> listJ = B.j(AFe1mSDK.CONVERSION, AFe1mSDK.LAUNCH, AFe1mSDK.INAPP, AFe1mSDK.MANUAL_PURCHASE_VALIDATION, AFe1mSDK.ARS_VALIDATE, AFe1mSDK.PURCHASE_VALIDATE, AFe1mSDK.ADREVENUE);
        int i = w + 75;
        d = i % 128;
        if (i % 2 != 0) {
            return listJ;
        }
        throw null;
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final void getCurrencyIso4217Code(@NotNull Map<String, Object> map) {
        Object objB;
        int i = w + 115;
        d = i % 128;
        if (i % 2 != 0) {
            Intrinsics.checkNotNullParameter(map, "");
            String str = this.copy.getCurrencyIso4217Code;
            if (str != null) {
                d = (w + 39) % 128;
                if (map.get("af_deeplink") != null) {
                    int i2 = w + 97;
                    d = i2 % 128;
                    if (i2 % 2 == 0) {
                        AFLogger.afDebugLog("Skip 'af' payload as deeplink was found by path");
                        throw null;
                    }
                    AFLogger.afDebugLog("Skip 'af' payload as deeplink was found by path");
                } else {
                    try {
                        p pVar = kotlin.r.b;
                        JSONObject jSONObject = new JSONObject(str);
                        jSONObject.put("isPush", "true");
                        map.put("af_deeplink", jSONObject.toString());
                        objB = Unit.a;
                    } catch (Throwable th) {
                        p pVar2 = kotlin.r.b;
                        objB = Z.b(th);
                    }
                    Throwable thA = kotlin.r.a(objB);
                    if (thA != null) {
                        AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.GENERAL, "Exception while trying to create JSONObject from pushPayload", thA, false, false, false, false, 120, null);
                    } else {
                        w = (d + 119) % 128;
                    }
                }
            }
            this.copy.getCurrencyIso4217Code = null;
            return;
        }
        Intrinsics.checkNotNullParameter(map, "");
        String str2 = this.copy.getCurrencyIso4217Code;
        throw null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:7:0x002e, code lost:
    
        if (r5.length() == 0) goto L12;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final java.lang.String getMonetizationNetwork(java.lang.String r5) {
        /*
            r4 = this;
            java.lang.Object[] r0 = new java.lang.Object[]{r4}
            int r1 = java.lang.System.identityHashCode(r4)
            r2 = 2080605438(0x7c0384fe, float:2.7315532E36)
            r3 = -2080605426(0xffffffff83fc7b0e, float:-1.4839481E-36)
            java.lang.Object r0 = getMediationNetwork(r0, r2, r3, r1)
            com.appsflyer.AppsFlyerProperties r0 = (com.appsflyer.AppsFlyerProperties) r0
            java.lang.String r1 = "collectAndroidId"
            r2 = 0
            boolean r0 = r0.getBoolean(r1, r2)
            r1 = 1
            r2 = 0
            if (r0 == r1) goto L20
            goto L31
        L20:
            if (r5 == 0) goto L35
            int r0 = com.appsflyer.internal.AFg1oSDK.w
            int r0 = r0 + 119
            int r0 = r0 % 128
            com.appsflyer.internal.AFg1oSDK.d = r0
            int r0 = r5.length()
            if (r0 != 0) goto L31
            goto L35
        L31:
            if (r5 == 0) goto L34
            return r5
        L34:
            return r2
        L35:
            boolean r5 = r4.AFKeystoreWrapper()
            if (r5 == 0) goto L50
            int r5 = com.appsflyer.internal.AFg1oSDK.d
            int r5 = r5 + 35
            int r5 = r5 % 128
            com.appsflyer.internal.AFg1oSDK.w = r5
            java.lang.String r5 = r4.AFInAppEventParameterName()
            int r0 = com.appsflyer.internal.AFg1oSDK.d
            int r0 = r0 + 81
            int r0 = r0 % 128
            com.appsflyer.internal.AFg1oSDK.w = r0
            return r5
        L50:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFg1oSDK.getMonetizationNetwork(java.lang.String):java.lang.String");
    }

    private final void getMediationNetwork(Map<String, Object> map) {
        try {
            long j = this.getMonetizationNetwork.getPackageManager().getPackageInfo(this.getMonetizationNetwork.getPackageName(), 0).firstInstallTime;
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd_HHmmssZ", Locale.US);
            simpleDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            map.put("installDate", simpleDateFormat.format(new Date(j)));
            int i = d + 111;
            w = i % 128;
            if (i % 2 != 0) {
                int i2 = 79 / 0;
            }
        } catch (Exception e) {
            AFLogger.afErrorLog("Exception while collecting install date. ", e);
        }
    }

    private void getMonetizationNetwork(@NotNull AFh1rSDK aFh1rSDK, String str, String str2, AFb1qSDK aFb1qSDK) throws PackageManager.NameNotFoundException {
        w = (d + ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND) % 128;
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        Map<String, Object> map = aFh1rSDK.AFAdRevenueData;
        if (aFh1rSDK.getCurrencyIso4217Code() == AFe1mSDK.CONVERSION) {
            int i = d + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED;
            w = i % 128;
            if (i % 2 != 0) {
                Intrinsics.checkNotNullExpressionValue(map, "");
                toString(map);
                copydefault(map);
                hashCode(map);
                AFa1zSDK.AFAdRevenueData(this.toString, this.component3);
                int i2 = 38 / 0;
            } else {
                Intrinsics.checkNotNullExpressionValue(map, "");
                toString(map);
                copydefault(map);
                hashCode(map);
                AFa1zSDK.AFAdRevenueData(this.toString, this.component3);
            }
        }
        Intrinsics.checkNotNullExpressionValue(map, "");
        copy(map);
        component3(map);
        component1((Map<String, ? extends Object>) map);
        getMonetizationNetwork(map, str2);
        getMediationNetwork(new Object[]{this, map, str}, 1763970144, -1763970135, System.identityHashCode(this));
        registerClient(map);
        if (aFb1qSDK != null) {
            aFb1qSDK.getRevenue(map);
        }
    }

    private void getMediationNetwork(@NotNull Map<String, Object> map, boolean z) {
        d = (w + 29) % 128;
        Intrinsics.checkNotNullParameter(map, "");
        map.put("platformextension", this.getCurrencyIso4217Code);
        if (z) {
            w = (d + 83) % 128;
            map.put("platform_extension_v2", this.getRevenue.getMediationNetwork());
        }
        d = (w + 5) % 128;
    }

    private void getCurrencyIso4217Code(@NotNull Map<String, Object> map, String str) {
        Intrinsics.checkNotNullParameter(map, "");
        if (((AppsFlyerProperties) getMediationNetwork(new Object[]{this}, 2080605438, -2080605426, System.identityHashCode(this))).getBoolean(AppsFlyerProperties.DEVICE_TRACKING_DISABLED, false)) {
            int i = d + 89;
            w = i % 128;
            if (i % 2 == 0) {
                map.put(AppsFlyerProperties.DEVICE_TRACKING_DISABLED, "true");
                return;
            } else {
                map.put(AppsFlyerProperties.DEVICE_TRACKING_DISABLED, "true");
                int i2 = 33 / 0;
                return;
            }
        }
        AFf1gSDK aFf1gSDK = this.equals;
        String str2 = (String) AFf1gSDK.getCurrencyIso4217Code(new Object[]{aFf1gSDK, this.component4}, -1198101809, 1198101809, System.identityHashCode(aFf1gSDK));
        if (!(str2 == null || str2.length() == 0)) {
            map.put("imei", str2);
        }
        String monetizationNetwork = getMonetizationNetwork(str);
        if (monetizationNetwork != null) {
            this.component4.getMediationNetwork("androidIdCached", monetizationNetwork);
            map.put("android_id", monetizationNetwork);
        } else {
            AFLogger.afInfoLog("Android ID was not collected.");
            d = (w + 39) % 128;
        }
        AFb1mSDK mediationNetwork = AFb1jSDK.getMediationNetwork(this.getMonetizationNetwork);
        if (mediationNetwork != null) {
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            Boolean bool = mediationNetwork.AFAdRevenueData;
            Intrinsics.checkNotNullExpressionValue(bool, "");
            linkedHashMap.put("isManual", bool);
            String str3 = mediationNetwork.getMonetizationNetwork;
            Intrinsics.checkNotNullExpressionValue(str3, "");
            linkedHashMap.put("val", str3);
            Boolean bool2 = mediationNetwork.getMediationNetwork;
            if (bool2 != null) {
                linkedHashMap.put("isLat", bool2);
            }
            map.put("oaid", linkedHashMap);
        }
    }

    private static /* synthetic */ Object getMediationNetwork(Object[] objArr) {
        AFg1oSDK aFg1oSDK = (AFg1oSDK) objArr[0];
        Map map = (Map) objArr[1];
        Intrinsics.checkNotNullParameter(map, "");
        AFi1pSDK aFi1pSDK = aFg1oSDK.component1.getMediationNetwork;
        AFi1rSDK mediationNetwork = aFi1pSDK != null ? aFi1pSDK.getMediationNetwork() : null;
        if (mediationNetwork != null) {
            map.put("network", mediationNetwork.getCurrencyIso4217Code);
            map.put("ivc", Boolean.valueOf(mediationNetwork.getMediationNetwork()));
            if (!((AppsFlyerProperties) getMediationNetwork(new Object[]{aFg1oSDK}, 2080605438, -2080605426, System.identityHashCode(aFg1oSDK))).getBoolean(AppsFlyerProperties.DISABLE_NETWORK_DATA, false)) {
                int i = (w + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION) % 128;
                d = i;
                String str = mediationNetwork.AFAdRevenueData;
                if (str != null) {
                    int i2 = i + 115;
                    w = i2 % 128;
                    if (i2 % 2 != 0) {
                        map.put("operator", str);
                        int i3 = 74 / 0;
                    } else {
                        map.put("operator", str);
                    }
                }
                String str2 = mediationNetwork.getRevenue;
                if (str2 != null) {
                    int i4 = w + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED;
                    d = i4 % 128;
                    if (i4 % 2 != 0) {
                        map.put("carrier", str2);
                        return null;
                    }
                    map.put("carrier", str2);
                    throw null;
                }
            }
        }
        return null;
    }

    private static void getMonetizationNetwork(@NotNull Map<String, Object> map, String str) {
        int i = d + 117;
        w = i % 128;
        if (i % 2 == 0) {
            Intrinsics.checkNotNullParameter(map, "");
            if (str != null) {
                d = (w + 99) % 128;
                map.put("phone", str);
            }
            w = (d + 15) % 128;
            return;
        }
        Intrinsics.checkNotNullParameter(map, "");
        throw null;
    }

    private void getMediationNetwork(@NotNull Map<String, Object> map, @NotNull String str) throws JSONException {
        int i = d + 7;
        w = i % 128;
        try {
            if (i % 2 == 0) {
                Intrinsics.checkNotNullParameter(map, "");
                Intrinsics.checkNotNullParameter(str, "");
                String strAFAdRevenueData = this.component4.AFAdRevenueData("prev_event_name", (String) null);
                if (strAFAdRevenueData != null) {
                    JSONObject jSONObject = new JSONObject();
                    jSONObject.put("prev_event_timestamp", this.component4.getCurrencyIso4217Code("prev_event_timestamp", -1L));
                    jSONObject.put("prev_event_name", strAFAdRevenueData);
                    map.put("prev_event", jSONObject);
                    w = (d + 27) % 128;
                }
                this.component4.getMediationNetwork("prev_event_name", str);
                this.component4.getMonetizationNetwork("prev_event_timestamp", System.currentTimeMillis());
                return;
            }
            Intrinsics.checkNotNullParameter(map, "");
            Intrinsics.checkNotNullParameter(str, "");
            this.component4.AFAdRevenueData("prev_event_name", (String) null);
            throw null;
        } catch (Exception e) {
            AFLogger.afErrorLog("Error while processing previous event.", e);
        }
    }

    private static /* synthetic */ Object getMonetizationNetwork(Object[] objArr) {
        AFg1oSDK aFg1oSDK = (AFg1oSDK) objArr[0];
        Map map = (Map) objArr[1];
        int i = d + 65;
        w = i % 128;
        if (i % 2 != 0) {
            Intrinsics.checkNotNullParameter(map, "");
            map.putAll(aFg1oSDK.hashCode.getCurrencyIso4217Code());
            int i2 = 13 / 0;
        } else {
            Intrinsics.checkNotNullParameter(map, "");
            map.putAll(aFg1oSDK.hashCode.getCurrencyIso4217Code());
        }
        d = (w + 87) % 128;
        return null;
    }

    private static File getCurrencyIso4217Code(String str) {
        int i = (w + 97) % 128;
        d = i;
        if (str != null) {
            int i2 = i + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED;
            w = i2 % 128;
            try {
                if (i2 % 2 == 0) {
                    if (StringsKt.g0(str).toString().length() > 0) {
                        d = (w + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED) % 128;
                        return new File(StringsKt.g0(str).toString());
                    }
                } else {
                    StringsKt.g0(str).toString().length();
                    throw null;
                }
            } catch (Throwable th) {
                AFLogger.afErrorLog(th.getMessage(), th);
            }
        }
        return null;
    }

    private static String getMonetizationNetwork(AFc1qSDK aFc1qSDK, String str) {
        return (String) getMediationNetwork(new Object[]{aFc1qSDK, str}, 381318279, -381318268, (int) System.currentTimeMillis());
    }

    @Override // com.appsflyer.internal.AFg1qSDK
    public final void getCurrencyIso4217Code(@NotNull AFh1rSDK aFh1rSDK) {
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        Map<String, Object> map = aFh1rSDK.AFAdRevenueData;
        Intrinsics.checkNotNullExpressionValue(map, "");
        map.put("open_referrer", aFh1rSDK.getMediationNetwork);
        String str = aFh1rSDK.component4;
        if (str != null) {
            int i = w + 43;
            d = i % 128;
            if (i % 2 != 0) {
                if (StringsKt.O(str)) {
                    return;
                }
                int i2 = w + 119;
                d = i2 % 128;
                if (i2 % 2 == 0) {
                    map.put("af_web_referrer", aFh1rSDK.component4);
                    int i3 = 26 / 0;
                    return;
                } else {
                    map.put("af_web_referrer", aFh1rSDK.component4);
                    return;
                }
            }
            StringsKt.O(str);
            throw null;
        }
    }

    @NotNull
    private String getMediationNetwork(@NotNull SimpleDateFormat simpleDateFormat) {
        int i = d + ContentType.LIVE;
        w = i % 128;
        if (i % 2 == 0) {
            Intrinsics.checkNotNullParameter(simpleDateFormat, "");
            String strAFAdRevenueData = this.component4.AFAdRevenueData("appsFlyerFirstInstall", (String) null);
            if (strAFAdRevenueData == null) {
                if (copydefault()) {
                    AFLogger.afDebugLog("AppsFlyer: first launch detected");
                    strAFAdRevenueData = simpleDateFormat.format(new Date());
                } else {
                    w = (d + 11) % 128;
                    strAFAdRevenueData = "";
                }
                this.component4.getMediationNetwork("appsFlyerFirstInstall", strAFAdRevenueData);
            }
            AFg1gSDK.i$default(AFLogger.INSTANCE, AFg1cSDK.GENERAL, AbstractC0147y.d("AppsFlyer: first launch date: ", strAFAdRevenueData), false, 4, null);
            Intrinsics.checkNotNullExpressionValue(strAFAdRevenueData, "");
            return strAFAdRevenueData;
        }
        Intrinsics.checkNotNullParameter(simpleDateFormat, "");
        this.component4.AFAdRevenueData("appsFlyerFirstInstall", (String) null);
        throw null;
    }

    @SuppressLint({"PrivateApi"})
    private static String getMediationNetwork(String str) {
        w = (d + 91) % 128;
        try {
            Object objInvoke = Class.forName("android.os.SystemProperties").getMethod("get", String.class).invoke(null, str);
            Intrinsics.e(objInvoke, "");
            String str2 = (String) objInvoke;
            w = (d + 43) % 128;
            return str2;
        } catch (Throwable th) {
            AFLogger.afErrorLog(th.getMessage(), th);
            return null;
        }
    }

    private static String getMediationNetwork(File file, String str) {
        return (String) getMediationNetwork(new Object[]{file, str}, -2094417185, 2094417192, (int) System.currentTimeMillis());
    }

    private static boolean getMediationNetwork(File file) {
        return ((Boolean) getMediationNetwork(new Object[]{file}, 1334456290, -1334456289, (int) System.currentTimeMillis())).booleanValue();
    }
}
