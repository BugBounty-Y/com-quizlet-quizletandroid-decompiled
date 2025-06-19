package com.appsflyer.internal;

import android.content.Context;
import android.graphics.Color;
import android.graphics.ImageFormat;
import android.graphics.drawable.Drawable;
import android.media.AudioTrack;
import android.os.Build;
import android.os.Process;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.ViewConfiguration;
import androidx.annotation.NonNull;
import androidx.compose.animation.d0;
import com.amazon.device.ads.DtbDeviceData;
import com.appsflyer.AFLogger;
import com.appsflyer.AppsFlyerLib;
import com.appsflyer.AppsFlyerProperties;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.pubmatic.sdk.video.c;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class AFd1oSDK {
    private static int $10 = 0;
    private static int $11 = 1;
    public static String AFAdRevenueData = null;
    private static int areAllFieldsValid = 0;
    private static int component1 = 0;
    private static int component3 = 0;
    private static int copy = 0;
    private static byte[] copydefault = null;
    private static String getRevenue = null;
    private static int hashCode = 1;
    private static short[] toString;
    private final AFj1fSDK component2;
    private final AFe1zSDK component4;
    private final AFc1pSDK getCurrencyIso4217Code;
    private final AppsFlyerProperties getMediationNetwork;
    private final AFd1lSDK getMonetizationNetwork;

    static {
        getMonetizationNetwork();
        AFAdRevenueData = "https://%sgcdsdk.%s/install_data/v5.0/";
        getRevenue = "https://%sonelink.%s/shortlink-sdk/v2";
        int i = hashCode + 37;
        copy = i % 128;
        if (i % 2 != 0) {
            throw null;
        }
    }

    public AFd1oSDK(AFd1lSDK aFd1lSDK, AFc1pSDK aFc1pSDK, AppsFlyerProperties appsFlyerProperties, AFe1zSDK aFe1zSDK, AFj1fSDK aFj1fSDK) {
        this.getMonetizationNetwork = aFd1lSDK;
        this.getCurrencyIso4217Code = aFc1pSDK;
        this.getMediationNetwork = appsFlyerProperties;
        this.component4 = aFe1zSDK;
        this.component2 = aFj1fSDK;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x00a1 A[PHI: r7
  0x00a1: PHI (r7v6 int) = (r7v5 int), (r7v52 int) binds: [B:27:0x009f, B:24:0x0092] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00a3 A[PHI: r7
  0x00a3: PHI (r7v49 int) = (r7v5 int), (r7v52 int) binds: [B:27:0x009f, B:24:0x0092] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void a(byte r12, short r13, int r14, int r15, int r16, java.lang.Object[] r17) {
        /*
            Method dump skipped, instructions count: 319
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFd1oSDK.a(byte, short, int, int, int, java.lang.Object[]):void");
    }

    public static /* synthetic */ Object getCurrencyIso4217Code(Object[] objArr, int i, int i2, int i3) {
        String str;
        String str2;
        String str3;
        int i4 = ~i;
        int i5 = ((~(i4 | i2 | i3)) * 521) + (i2 * 522) + (i * (-520));
        int i6 = ~(i | (~i2));
        int i7 = ((i6 | (~(i2 | (~i3) | i4))) * 521) + (i6 * (-1042)) + i5;
        if (i7 == 1) {
            AFd1oSDK aFd1oSDK = (AFd1oSDK) objArr[0];
            AFh1mSDK aFh1mSDK = (AFh1mSDK) objArr[1];
            AFd1nSDK revenue = aFd1oSDK.getRevenue(new AFd1cSDK(aFh1mSDK.component1, aFh1mSDK.AFAdRevenueData(), "POST", Collections.EMPTY_MAP, true), new AFd1eSDK());
            hashCode = (copy + 67) % 128;
            return revenue;
        }
        if (i7 != 2) {
            AFd1oSDK aFd1oSDK2 = (AFd1oSDK) objArr[0];
            HashMap map = new HashMap();
            map.put("build_number", "6.17.0");
            map.put("counter", Integer.valueOf(aFd1oSDK2.getCurrencyIso4217Code.getMonetizationNetwork.AFAdRevenueData("appsFlyerCount", 0)));
            map.put(DtbDeviceData.DEVICE_DATA_MODEL_KEY, Build.MODEL);
            Object[] objArr2 = new Object[1];
            a((byte) (83 - MotionEvent.axisFromString("")), (short) (Gravity.getAbsoluteGravity(0, 0) + 43), (-88) - ((Process.getThreadPriority(0) + 20) >> 6), MotionEvent.axisFromString("") + 2017627781, KeyEvent.keyCodeFromString("") + 1432018452, objArr2);
            map.put(((String) objArr2[0]).intern(), Build.BRAND);
            map.put("sdk", Integer.toString(Build.VERSION.SDK_INT));
            Context context = aFd1oSDK2.getCurrencyIso4217Code.getRevenue.getMonetizationNetwork;
            map.put("app_version_name", AFj1iSDK.getMediationNetwork(context, context.getPackageName()));
            map.put("app_id", aFd1oSDK2.getCurrencyIso4217Code.getRevenue.getMonetizationNetwork.getPackageName());
            map.put("platformextension", new AFa1vSDK().getMonetizationNetwork());
            hashCode = (copy + 93) % 128;
            return map;
        }
        AFd1oSDK aFd1oSDK3 = (AFd1oSDK) objArr[0];
        boolean zBooleanValue = ((Boolean) objArr[1]).booleanValue();
        boolean zBooleanValue2 = ((Boolean) objArr[2]).booleanValue();
        String str4 = (String) objArr[3];
        ((Number) objArr[4]).intValue();
        AFe1zSDK aFe1zSDK = aFd1oSDK3.component4;
        Intrinsics.checkNotNullParameter(str4, "");
        if (zBooleanValue) {
            str = AFe1zSDK.getRevenue;
        } else {
            str = AFe1zSDK.getMediationNetwork;
            copy = (hashCode + 47) % 128;
        }
        if (zBooleanValue2) {
            hashCode = (copy + 115) % 128;
            str2 = "stg";
        } else {
            str2 = "";
        }
        if (AFe1zSDK.AFAdRevenueData()) {
            str3 = (String) aFe1zSDK.AFAdRevenueData.getValue();
        } else {
            copy = (hashCode + 33) % 128;
            str3 = "";
        }
        AFd1cSDK aFd1cSDK = new AFd1cSDK(d0.s(new Object[]{str3, str2, aFe1zSDK.getMediationNetwork(), str4}, 4, str, ""), "GET");
        aFd1cSDK.component4 = 1500;
        return aFd1oSDK3.getRevenue(aFd1cSDK, new AFd1bSDK());
    }

    private Map<String, Object> getMediationNetwork() {
        return (Map) getCurrencyIso4217Code(new Object[]{this}, -1717475171, 1717475171, System.identityHashCode(this));
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x007f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.appsflyer.internal.AFd1nSDK<java.lang.String> AFAdRevenueData(java.util.Map<java.lang.String, java.lang.Object> r12, java.lang.String r13, java.lang.String r14) {
        /*
            Method dump skipped, instructions count: 248
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFd1oSDK.AFAdRevenueData(java.util.Map, java.lang.String, java.lang.String):com.appsflyer.internal.AFd1nSDK");
    }

    public final AFd1nSDK<String> getMonetizationNetwork(Map<String, Object> map, String str) {
        hashCode = (copy + 117) % 128;
        try {
            Object[] objArr = {map, str};
            Map map2 = AFa1kSDK.i;
            Object method = map2.get(317123644);
            if (method == null) {
                method = ((Class) AFa1kSDK.getCurrencyIso4217Code(Gravity.getAbsoluteGravity(0, 0) + 196, (char) (1 - (ViewConfiguration.getZoomControlsTimeout() > 0L ? 1 : (ViewConfiguration.getZoomControlsTimeout() == 0L ? 0 : -1))), 37 - TextUtils.getOffsetAfter("", 0))).getMethod("getMediationNetwork", Map.class, String.class);
                map2.put(317123644, method);
            }
            byte[] bArr = (byte[]) ((Method) method).invoke(null, objArr);
            hashCode = (copy + 69) % 128;
            AFj1fSDK aFj1fSDK = this.component2;
            return getRevenue(new AFd1cSDK(aFj1fSDK.getCurrencyIso4217Code(aFj1fSDK.getMonetizationNetwork.AFAdRevenueData("https://%svalidate-and-log.%s/api/v1.0/android/validateAndLog?app_id=")), bArr, "POST", Collections.EMPTY_MAP, true), new AFd1eSDK());
        } catch (Throwable th) {
            try {
                Throwable cause = th.getCause();
                if (cause != null) {
                    throw cause;
                }
                throw th;
            } catch (Throwable th2) {
                AFLogger.INSTANCE.e(AFg1cSDK.PURCHASE_VALIDATION, "AFFinalizer: reflection init failed.", th2, false, false);
                return null;
            }
        }
    }

    public final AFd1nSDK<Map<String, Object>> getRevenue(String str, String str2) {
        AFd1nSDK<Map<String, Object>> revenue = getRevenue(AFd1fSDK.getMonetizationNetwork(this.getCurrencyIso4217Code.getRevenue.getMonetizationNetwork.getPackageName(), AFb1iSDK.getRevenue(this.getCurrencyIso4217Code.getMonetizationNetwork), str, str2), new AFd1iSDK());
        copy = (hashCode + 79) % 128;
        return revenue;
    }

    public final AFd1nSDK<String> getMediationNetwork(AFh1mSDK aFh1mSDK) {
        return (AFd1nSDK) getCurrencyIso4217Code(new Object[]{this, aFh1mSDK}, -44698683, 44698684, System.identityHashCode(this));
    }

    public final AFd1nSDK<Map<String, String>> getRevenue(@NonNull String str, @NonNull String str2, @NonNull UUID uuid, @NonNull String str3) {
        String string = uuid.toString();
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(getRevenue, AppsFlyerLib.getInstance().getHostPrefix(), ((AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).getHostName()));
        sb.append("/");
        sb.append(str);
        sb.append("?id=");
        sb.append(str2);
        String string2 = sb.toString();
        Map map = (Map) getCurrencyIso4217Code(new Object[]{this}, -1717475171, 1717475171, System.identityHashCode(this));
        String strValueOf = String.valueOf(map.get("build_number"));
        HashMap map2 = new HashMap();
        map2.put("Af-UUID", uuid.toString());
        map2.put("Af-Meta-Sdk-Ver", strValueOf);
        map2.put("Af-Meta-Counter", String.valueOf(map.get("counter")));
        map2.put("Af-Meta-Model", String.valueOf(map.get(DtbDeviceData.DEVICE_DATA_MODEL_KEY)));
        map2.put("Af-Meta-Platform", String.valueOf(map.get("platformextension")));
        map2.put("Af-Meta-System-Version", String.valueOf(map.get("sdk")));
        Object[] objArr = new Object[1];
        a((byte) (88 - Color.green(0)), (short) (22 - (TypedValue.complexToFloat(0) > DefinitionKt.NO_Float_VALUE ? 1 : (TypedValue.complexToFloat(0) == DefinitionKt.NO_Float_VALUE ? 0 : -1))), (-88) - Gravity.getAbsoluteGravity(0, 0), Drawable.resolveOpacity(0, 0) + 2017627768, 1432018418 - ImageFormat.getBitsPerPixel(0), objArr);
        map2.put(((String) objArr[0]).intern(), getMonetizationNetwork(str3, string, "GET", string, str, str2, strValueOf));
        AFd1nSDK<Map<String, String>> revenue = getRevenue(new AFd1cSDK(string2, null, "GET", map2, false), new AFd1dSDK());
        hashCode = (copy + 5) % 128;
        return revenue;
    }

    public final AFd1nSDK<String> getMonetizationNetwork(@NonNull String str, @NonNull Map<String, String> map, String str2, @NonNull UUID uuid, @NonNull String str3) {
        String string = uuid.toString();
        HashMap map2 = new HashMap();
        map2.put("ttl", "-1");
        map2.put("uuid", string);
        map2.put("data", map);
        map2.put("meta", (Map) getCurrencyIso4217Code(new Object[]{this}, -1717475171, 1717475171, System.identityHashCode(this)));
        if (str2 != null) {
            int i = hashCode + 81;
            copy = i % 128;
            if (i % 2 != 0) {
                map2.put("brand_domain", str2);
                int i2 = 19 / 0;
            } else {
                map2.put("brand_domain", str2);
            }
            hashCode = (copy + 1) % 128;
        }
        String string2 = AFg1lSDK.getCurrencyIso4217Code(map2).toString();
        HashMap map3 = new HashMap();
        Object[] objArr = new Object[1];
        a((byte) (88 - TextUtils.indexOf("", "", 0)), (short) (((Process.getThreadPriority(0) + 20) >> 6) + 22), (AudioTrack.getMinVolume() > DefinitionKt.NO_Float_VALUE ? 1 : (AudioTrack.getMinVolume() == DefinitionKt.NO_Float_VALUE ? 0 : -1)) - 88, Color.rgb(0, 0, 0) + 2034404984, 1432018419 - (ViewConfiguration.getScrollBarSize() >> 8), objArr);
        map3.put(((String) objArr[0]).intern(), getMonetizationNetwork(str3, string, "POST", string2));
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(getRevenue, AppsFlyerLib.getInstance().getHostPrefix(), AFa1tSDK.getCurrencyIso4217Code().getHostName()));
        sb.append("/");
        sb.append(str);
        AFd1nSDK<String> revenue = getRevenue(new AFd1cSDK(sb.toString(), string2.getBytes(Charset.defaultCharset()), "POST", map3, false), new AFd1eSDK(), true);
        int i3 = hashCode + 67;
        copy = i3 % 128;
        if (i3 % 2 != 0) {
            int i4 = 99 / 0;
        }
        return revenue;
    }

    @NonNull
    public final AFd1nSDK<AFa1mSDK> AFAdRevenueData(AFa1pSDK aFa1pSDK) {
        AFd1nSDK<AFa1mSDK> revenue = getRevenue(new AFd1cSDK(aFa1pSDK.component1, AFg1lSDK.getCurrencyIso4217Code(aFa1pSDK.AFAdRevenueData).toString().getBytes(Charset.defaultCharset()), "POST", Collections.EMPTY_MAP, aFa1pSDK.getMonetizationNetwork()), new AFa1rSDK());
        int i = hashCode + 91;
        copy = i % 128;
        if (i % 2 != 0) {
            int i2 = 24 / 0;
        }
        return revenue;
    }

    public final AFd1nSDK<String> getRevenue(@NonNull String str) {
        AFd1cSDK aFd1cSDK = new AFd1cSDK(str, null, "GET", Collections.EMPTY_MAP, false);
        aFd1cSDK.component4 = c.a.DEFAULT_MEDIA_URI_TIMEOUT;
        aFd1cSDK.getCurrencyIso4217Code = false;
        AFd1nSDK<String> revenue = getRevenue(aFd1cSDK, new AFd1eSDK());
        int i = hashCode + 19;
        copy = i % 128;
        if (i % 2 == 0) {
            return revenue;
        }
        throw null;
    }

    public final AFd1mSDK getRevenue(Map<String, Object> map, String str) {
        copy = (hashCode + 65) % 128;
        try {
            try {
                Object[] objArr = {map, str};
                Map map2 = AFa1kSDK.i;
                Object method = map2.get(317123644);
                if (method == null) {
                    method = ((Class) AFa1kSDK.getCurrencyIso4217Code(197 - (SystemClock.uptimeMillis() > 0L ? 1 : (SystemClock.uptimeMillis() == 0L ? 0 : -1)), (char) ((-1) - TextUtils.indexOf((CharSequence) "", '0', 0)), TextUtils.lastIndexOf("", '0', 0, 0) + 38)).getMethod("getMediationNetwork", Map.class, String.class);
                    map2.put(317123644, method);
                }
                byte[] bArr = (byte[]) ((Method) method).invoke(null, objArr);
                if (bArr == null) {
                    AFLogger.INSTANCE.e(AFg1cSDK.GENERAL, "AFFinalizer: failed to create bytes.", new IllegalArgumentException("Failed to create bytes from proxyData, bytes are null"), false, false);
                    return null;
                }
                copy = (hashCode + 19) % 128;
                return new AFd1mSDK(this.getCurrencyIso4217Code, bArr);
            } catch (Throwable th) {
                Throwable cause = th.getCause();
                if (cause != null) {
                    throw cause;
                }
                throw th;
            }
        } catch (Throwable th2) {
            AFLogger.INSTANCE.e(AFg1cSDK.GENERAL, "AFFinalizer: reflection init failed.", th2, false, false);
            return null;
        }
    }

    private static String getMonetizationNetwork(String str, String str2, String... strArr) throws NoSuchAlgorithmException, InvalidKeyException {
        ArrayList arrayList = new ArrayList(Arrays.asList(strArr));
        arrayList.add(1, "v2");
        String strJoin = TextUtils.join("\u2063", (String[]) arrayList.toArray(new String[0]));
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append(str2);
        sb.append("v2");
        String revenue = AFj1cSDK.getRevenue(strJoin, sb.toString());
        int i = hashCode + 41;
        copy = i % 128;
        if (i % 2 == 0) {
            return revenue;
        }
        throw null;
    }

    private <T> AFd1nSDK<T> getRevenue(AFd1cSDK aFd1cSDK, AFe1ySDK<T> aFe1ySDK) {
        AFd1nSDK<T> revenue;
        int i = hashCode + 69;
        copy = i % 128;
        if (i % 2 != 0) {
            revenue = getRevenue(aFd1cSDK, aFe1ySDK, getRevenue());
            int i2 = 32 / 0;
        } else {
            revenue = getRevenue(aFd1cSDK, aFe1ySDK, getRevenue());
        }
        int i3 = hashCode + 71;
        copy = i3 % 128;
        if (i3 % 2 == 0) {
            return revenue;
        }
        throw null;
    }

    public static void getMonetizationNetwork() {
        component1 = -411944536;
        areAllFieldsValid = 1624197239;
        component3 = -898995602;
        copydefault = new byte[]{-107, -75, -81, 99, 21, -75, 105, -80, 24, 72, -87, 71, -114, 87, 14, -80, 57};
    }

    private boolean getRevenue() {
        if (this.getMediationNetwork.getBoolean(AppsFlyerProperties.HTTP_CACHE, true)) {
            return false;
        }
        int i = copy;
        int i2 = i + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED;
        hashCode = i2 % 128;
        boolean z = !(i2 % 2 == 0);
        hashCode = (i + 79) % 128;
        return z;
    }

    private <T> AFd1nSDK<T> getRevenue(AFd1cSDK aFd1cSDK, AFe1ySDK<T> aFe1ySDK, boolean z) {
        aFd1cSDK.getMediationNetwork = z;
        AFd1lSDK aFd1lSDK = this.getMonetizationNetwork;
        AFd1nSDK<T> aFd1nSDK = new AFd1nSDK<>(aFd1cSDK, aFd1lSDK.getRevenue, aFd1lSDK.getMonetizationNetwork, aFe1ySDK);
        copy = (hashCode + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION) % 128;
        return aFd1nSDK;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0090  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.appsflyer.internal.AFd1nSDK<java.lang.String> getCurrencyIso4217Code(java.util.Map<java.lang.String, java.lang.Object> r11, java.lang.String r12, java.lang.String r13) {
        /*
            Method dump skipped, instructions count: 228
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFd1oSDK.getCurrencyIso4217Code(java.util.Map, java.lang.String, java.lang.String):com.appsflyer.internal.AFd1nSDK");
    }

    @NonNull
    public final AFd1nSDK<AFi1wSDK> getRevenue(boolean z, boolean z2, @NonNull String str, int i) {
        return (AFd1nSDK) getCurrencyIso4217Code(new Object[]{this, Boolean.valueOf(z), Boolean.valueOf(z2), str, Integer.valueOf(i)}, 662152322, -662152320, i);
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x010b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.appsflyer.internal.AFd1nSDK<java.lang.String> getCurrencyIso4217Code(com.appsflyer.internal.AFh1rSDK r13, java.lang.String r14, com.appsflyer.internal.AFc1iSDK r15) {
        /*
            Method dump skipped, instructions count: 337
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFd1oSDK.getCurrencyIso4217Code(com.appsflyer.internal.AFh1rSDK, java.lang.String, com.appsflyer.internal.AFc1iSDK):com.appsflyer.internal.AFd1nSDK");
    }
}
