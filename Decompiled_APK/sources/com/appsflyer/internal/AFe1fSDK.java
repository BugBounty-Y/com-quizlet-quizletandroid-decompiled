package com.appsflyer.internal;

import androidx.glance.appwidget.protobuf.Z;
import com.appsflyer.AFPurchaseDetails;
import com.appsflyer.AppsFlyerInAppPurchaseValidationCallback;
import com.appsflyer.AppsFlyerProperties;
import com.appsflyer.internal.components.network.http.ResponseNetwork;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.V;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.r;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class AFe1fSDK extends AFe1gSDK {

    @NotNull
    private final AppsFlyerProperties component2;

    @NotNull
    private final AFj1hSDK copy;

    @NotNull
    private final AFPurchaseDetails equals;
    private final AppsFlyerInAppPurchaseValidationCallback hashCode;
    private final Map<String, String> toString;

    public static final class AFa1tSDK extends RuntimeException {
    }

    public /* synthetic */ AFe1fSDK(AFc1dSDK aFc1dSDK, AppsFlyerProperties appsFlyerProperties, AFPurchaseDetails aFPurchaseDetails, Map map, AppsFlyerInAppPurchaseValidationCallback appsFlyerInAppPurchaseValidationCallback, AFj1hSDK aFj1hSDK, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(aFc1dSDK, appsFlyerProperties, aFPurchaseDetails, map, appsFlyerInAppPurchaseValidationCallback, (i & 32) != 0 ? new AFj1gSDK() : aFj1hSDK);
    }

    @Override // com.appsflyer.internal.AFe1gSDK
    @NotNull
    public final String AFAdRevenueData(@NotNull Map<String, Object> map) {
        Intrinsics.checkNotNullParameter(map, "");
        return this.copy.getRevenue();
    }

    @Override // com.appsflyer.internal.AFe1gSDK
    public final void getMediationNetwork(@NotNull Map<String, Object> map, String str) {
        Intrinsics.checkNotNullParameter(map, "");
        super.getMediationNetwork(map, str);
        List listJ = B.j(this.equals.getPurchaseToken(), this.equals.getProductId(), this.equals.getPrice(), this.equals.getCurrency());
        if (listJ == null || !listJ.isEmpty()) {
            Iterator it2 = listJ.iterator();
            while (it2.hasNext()) {
                if (((String) it2.next()).length() == 0) {
                    throw new AFa1tSDK();
                }
            }
        }
        map.put("purchase_token", this.equals.getPurchaseToken());
        map.put("product_id", this.equals.getProductId());
        map.put("revenue", this.equals.getPrice());
        map.put("currency", this.equals.getCurrency());
        map.put("purchase_type", this.equals.getPurchaseType().getValue());
        Map<String, String> map2 = this.toString;
        if (map2 != null && !map2.isEmpty()) {
            map.put("extra_event_values", this.toString);
        }
        String string = this.component2.getString(AppsFlyerProperties.ADDITIONAL_CUSTOM_DATA);
        map.put("custom_data", (string == null || string.length() == 0) ? V.c() : AFj1eSDK.getCurrencyIso4217Code(new JSONObject(string)));
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final void getRevenue() {
        Object objB;
        super.getRevenue();
        Throwable thComponent4 = component4();
        if (thComponent4 != null && !(thComponent4 instanceof AFe1oSDK)) {
            if (thComponent4 instanceof AFe1nSDK) {
                getRevenue("No dev key", -1);
            } else if (thComponent4 instanceof AFa1tSDK) {
                getRevenue("One or more of provided arguments is empty", -1);
            } else {
                getRevenue("Error while sending request to server", -1);
            }
        }
        ResponseNetwork responseNetwork = ((AFe1dSDK) this).component1;
        if (responseNetwork != null) {
            if (responseNetwork.getStatusCode() != 200) {
                AppsFlyerInAppPurchaseValidationCallback appsFlyerInAppPurchaseValidationCallback = this.hashCode;
                if (appsFlyerInAppPurchaseValidationCallback != null) {
                    appsFlyerInAppPurchaseValidationCallback.onInAppPurchaseValidationError(V.f(new Pair("error_code", Integer.valueOf(responseNetwork.getStatusCode())), new Pair("error_message", responseNetwork.getBody())));
                    return;
                }
                return;
            }
            try {
                p pVar = r.b;
                AppsFlyerInAppPurchaseValidationCallback appsFlyerInAppPurchaseValidationCallback2 = this.hashCode;
                if (appsFlyerInAppPurchaseValidationCallback2 != null) {
                    appsFlyerInAppPurchaseValidationCallback2.onInAppPurchaseValidationFinished(AFj1eSDK.getCurrencyIso4217Code(new JSONObject((String) responseNetwork.getBody())));
                    objB = Unit.a;
                } else {
                    objB = null;
                }
            } catch (Throwable th) {
                p pVar2 = r.b;
                objB = Z.b(th);
            }
            if (r.a(objB) != null) {
                getRevenue("Error while trying to parse JSON response", responseNetwork.getStatusCode());
            }
        }
    }

    @Override // com.appsflyer.internal.AFe1gSDK
    public final AFd1nSDK<String> AFAdRevenueData(@NotNull Map<String, Object> map, @NotNull String str, String str2) {
        Intrinsics.checkNotNullParameter(map, "");
        Intrinsics.checkNotNullParameter(str, "");
        return this.component4.getMonetizationNetwork(map, str);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    private AFe1fSDK(@NotNull AFc1dSDK aFc1dSDK, @NotNull AppsFlyerProperties appsFlyerProperties, @NotNull AFPurchaseDetails aFPurchaseDetails, Map<String, String> map, AppsFlyerInAppPurchaseValidationCallback appsFlyerInAppPurchaseValidationCallback, @NotNull AFj1hSDK aFj1hSDK) {
        super(AFe1mSDK.MANUAL_PURCHASE_VALIDATION, new AFe1mSDK[]{AFe1mSDK.RC_CDN, AFe1mSDK.FETCH_ADVERTISING_ID}, aFc1dSDK, null, V.c());
        Intrinsics.checkNotNullParameter(aFc1dSDK, "");
        Intrinsics.checkNotNullParameter(appsFlyerProperties, "");
        Intrinsics.checkNotNullParameter(aFPurchaseDetails, "");
        Intrinsics.checkNotNullParameter(aFj1hSDK, "");
        this.component2 = appsFlyerProperties;
        this.equals = aFPurchaseDetails;
        this.toString = map;
        this.hashCode = appsFlyerInAppPurchaseValidationCallback;
        this.copy = aFj1hSDK;
        this.AFAdRevenueData.add(AFe1mSDK.CONVERSION);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AFe1fSDK(@NotNull AFc1dSDK aFc1dSDK, @NotNull AppsFlyerProperties appsFlyerProperties, @NotNull AFPurchaseDetails aFPurchaseDetails, Map<String, String> map, AppsFlyerInAppPurchaseValidationCallback appsFlyerInAppPurchaseValidationCallback) {
        this(aFc1dSDK, appsFlyerProperties, aFPurchaseDetails, map, appsFlyerInAppPurchaseValidationCallback, null, 32, null);
        Intrinsics.checkNotNullParameter(aFc1dSDK, "");
        Intrinsics.checkNotNullParameter(appsFlyerProperties, "");
        Intrinsics.checkNotNullParameter(aFPurchaseDetails, "");
    }

    private final void getRevenue(String str, int i) {
        AppsFlyerInAppPurchaseValidationCallback appsFlyerInAppPurchaseValidationCallback = this.hashCode;
        if (appsFlyerInAppPurchaseValidationCallback != null) {
            appsFlyerInAppPurchaseValidationCallback.onInAppPurchaseValidationError(V.f(new Pair("error_code", Integer.valueOf(i)), new Pair("error_message", str)));
        }
    }
}
