package com.appsflyer.internal;

import android.content.Intent;
import android.graphics.ImageFormat;
import android.net.Uri;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.ViewConfiguration;
import com.appsflyer.migration.internal.MigrationDataProvider;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.U;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AFh1pSDK implements AFh1uSDK {

    @NotNull
    private final AFj1sSDK AFAdRevenueData;
    private boolean component1;
    private boolean component2;

    @NotNull
    private final AFc1pSDK getCurrencyIso4217Code;
    private Long getMediationNetwork;
    private JSONObject getMonetizationNetwork;
    private Long getRevenue;

    public /* synthetic */ class AFa1tSDK {
        public static final /* synthetic */ int[] getMediationNetwork;

        static {
            int[] iArr = new int[AFe1mSDK.values().length];
            try {
                iArr[AFe1mSDK.LAUNCH.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[AFe1mSDK.ATTR.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            getMediationNetwork = iArr;
        }
    }

    public AFh1pSDK(@NotNull AFc1pSDK aFc1pSDK, @NotNull AFj1sSDK aFj1sSDK) {
        Intrinsics.checkNotNullParameter(aFc1pSDK, "");
        Intrinsics.checkNotNullParameter(aFj1sSDK, "");
        this.getCurrencyIso4217Code = aFc1pSDK;
        this.AFAdRevenueData = aFj1sSDK;
    }

    private final void getMonetizationNetwork(String str, AFh1rSDK aFh1rSDK, JSONObject jSONObject) {
        HashMap map = new HashMap();
        map.put(str, jSONObject);
        HashMap map2 = new HashMap();
        map2.put("branch", map);
        HashMap map3 = new HashMap();
        map3.put("external", map2);
        aFh1rSDK.getMediationNetwork(map3);
        Map<String, Object> map4 = aFh1rSDK.AFAdRevenueData;
        Intrinsics.checkNotNullExpressionValue(map4, "");
        AFe1mSDK currencyIso4217Code = aFh1rSDK.getCurrencyIso4217Code();
        Intrinsics.checkNotNullExpressionValue(currencyIso4217Code, "");
        getMonetizationNetwork(map4, currencyIso4217Code);
    }

    @Override // com.appsflyer.internal.AFh1uSDK
    public final void getCurrencyIso4217Code(@NotNull AFh1rSDK aFh1rSDK) {
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        JSONObject attributionData = MigrationDataProvider.getAttributionData();
        if (attributionData != null) {
            getMonetizationNetwork("attr", aFh1rSDK, attributionData);
            this.component2 = true;
        }
        MigrationDataProvider.clear();
    }

    @Override // com.appsflyer.internal.AFh1uSDK
    public final void getMediationNetwork(@NotNull AFh1rSDK aFh1rSDK) {
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        JSONObject jSONObject = this.getMonetizationNetwork;
        if (jSONObject != null) {
            Intrinsics.d(jSONObject);
            getMonetizationNetwork("attr", aFh1rSDK, jSONObject);
        } else {
            JSONObject currencyIso4217Code = getCurrencyIso4217Code();
            if (currencyIso4217Code != null) {
                getMonetizationNetwork("attr", aFh1rSDK, currencyIso4217Code);
            }
        }
        MigrationDataProvider.clear();
    }

    @Override // com.appsflyer.internal.AFh1uSDK
    public final void getRevenue(@NotNull AFf1uSDK aFf1uSDK, @NotNull Function0<Unit> function0) {
        JSONObject currencyIso4217Code;
        Intrinsics.checkNotNullParameter(aFf1uSDK, "");
        Intrinsics.checkNotNullParameter(function0, "");
        if (this.getCurrencyIso4217Code.getMonetizationNetwork.AFAdRevenueData("appsFlyerCount", 0) == 1 && aFf1uSDK.getMonetizationNetwork == AFe1mSDK.CONVERSION && this.AFAdRevenueData.AFAdRevenueData() && !getMonetizationNetwork() && (currencyIso4217Code = getCurrencyIso4217Code()) != null) {
            this.getMonetizationNetwork = currencyIso4217Code;
            function0.invoke();
        }
    }

    @Override // com.appsflyer.internal.AFh1uSDK
    public final void u_(@NotNull Intent intent, @NotNull AFa1oSDK aFa1oSDK) throws Throwable {
        Intrinsics.checkNotNullParameter(intent, "");
        Intrinsics.checkNotNullParameter(aFa1oSDK, "");
        if (MigrationDataProvider.waitForDeepLinkingData(0L) != null) {
            this.component1 = true;
            return;
        }
        Uri data = intent.getData();
        if (data == null) {
            return;
        }
        try {
            Object[] objArr = {data, aFa1oSDK};
            Map map = AFa1kSDK.i;
            Object declaredConstructor = map.get(-1523018365);
            if (declaredConstructor == null) {
                declaredConstructor = ((Class) AFa1kSDK.getCurrencyIso4217Code(KeyEvent.getDeadChar(0, 0), (char) ((-1) - ImageFormat.getBitsPerPixel(0)), 38 - (ViewConfiguration.getScrollFriction() > DefinitionKt.NO_Float_VALUE ? 1 : (ViewConfiguration.getScrollFriction() == DefinitionKt.NO_Float_VALUE ? 0 : -1)))).getDeclaredConstructor(Uri.class, AFa1oSDK.class);
                map.put(-1523018365, declaredConstructor);
            }
            Object objNewInstance = ((Constructor) declaredConstructor).newInstance(objArr);
            Object method = map.get(1191605722);
            if (method == null) {
                method = ((Class) AFa1kSDK.getCurrencyIso4217Code((-1) - MotionEvent.axisFromString(""), (char) TextUtils.indexOf("", ""), 37 - TextUtils.indexOf("", ""))).getMethod("getRevenue", null);
                map.put(1191605722, method);
            }
            Object objInvoke = ((Method) method).invoke(objNewInstance, null);
            Object method2 = map.get(1984406162);
            if (method2 == null) {
                method2 = ((Class) AFa1kSDK.getCurrencyIso4217Code((ViewConfiguration.getKeyRepeatTimeout() >> 16) + 37, (char) (TextUtils.indexOf("", "") + 44102), (TypedValue.complexToFraction(0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE) > DefinitionKt.NO_Float_VALUE ? 1 : (TypedValue.complexToFraction(0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE) == DefinitionKt.NO_Float_VALUE ? 0 : -1)) + 50)).getMethod("getRevenue", null);
                map.put(1984406162, method2);
            }
            this.component1 = !((Boolean) ((Method) method2).invoke(objInvoke, null)).booleanValue();
        } catch (Throwable th) {
            Throwable cause = th.getCause();
            if (cause == null) {
                throw th;
            }
            throw cause;
        }
    }

    private final JSONObject getCurrencyIso4217Code() {
        long jCurrentTimeMillis = System.currentTimeMillis();
        JSONObject jSONObjectWaitForAttributionData = MigrationDataProvider.waitForAttributionData(3000L);
        if (jSONObjectWaitForAttributionData != null) {
            this.getMediationNetwork = Long.valueOf(System.currentTimeMillis() - jCurrentTimeMillis);
        }
        return jSONObjectWaitForAttributionData;
    }

    @Override // com.appsflyer.internal.AFh1uSDK
    public final void getMediationNetwork() {
        this.component1 = false;
        MigrationDataProvider.clear();
    }

    private final void getMonetizationNetwork(Map<String, Object> map, AFe1mSDK aFe1mSDK) {
        Long l;
        int i = AFa1tSDK.getMediationNetwork[aFe1mSDK.ordinal()];
        if (i != 1) {
            l = i != 2 ? null : this.getMediationNetwork;
        } else {
            l = this.getRevenue;
        }
        if (l != null) {
            long jLongValue = l.longValue();
            Map<String, Object> revenue = com.appsflyer.internal.AFa1tSDK.getRevenue(map);
            Intrinsics.checkNotNullExpressionValue(revenue, "");
            revenue.put("migration", U.b(new Pair("delay", Long.valueOf(jLongValue))));
        }
    }

    @Override // com.appsflyer.internal.AFh1uSDK
    public final boolean getRevenue() {
        return this.component1;
    }

    @Override // com.appsflyer.internal.AFh1uSDK
    public final boolean getMonetizationNetwork() {
        return this.component2;
    }

    @Override // com.appsflyer.internal.AFh1uSDK
    public final void getMonetizationNetwork(@NotNull AFh1rSDK aFh1rSDK) {
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        long jCurrentTimeMillis = System.currentTimeMillis();
        JSONObject jSONObjectWaitForDeepLinkingData = MigrationDataProvider.waitForDeepLinkingData(3000L);
        if (jSONObjectWaitForDeepLinkingData != null) {
            this.getRevenue = Long.valueOf(System.currentTimeMillis() - jCurrentTimeMillis);
            getMonetizationNetwork("dl", aFh1rSDK, jSONObjectWaitForDeepLinkingData);
        }
        MigrationDataProvider.clear();
    }
}
