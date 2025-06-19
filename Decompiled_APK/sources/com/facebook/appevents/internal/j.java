package com.facebook.appevents.internal;

import android.os.Bundle;
import com.facebook.appevents.p;
import com.facebook.appevents.q;
import com.facebook.appevents.r;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.facebook.o;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3559x2;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Currency;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class j {
    public static final p a = new p(o.a());

    public static i a(String str, Bundle bundle, q qVar, JSONObject jSONObject, JSONObject jSONObject2) {
        if (Intrinsics.b(str, "subs")) {
            Map map = q.b;
            String string = Boolean.toString(jSONObject.optBoolean("autoRenewing", false));
            Intrinsics.checkNotNullExpressionValue(string, "toString(\n              …      )\n                )");
            AbstractC3559x2.a("fb_iap_subs_auto_renewing", string, bundle, qVar);
            String strOptString = jSONObject2.optString("subscriptionPeriod");
            Intrinsics.checkNotNullExpressionValue(strOptString, "skuDetailsJSON.optString…_IAP_SUBSCRIPTION_PERIOD)");
            AbstractC3559x2.a("fb_iap_subs_period", strOptString, bundle, qVar);
            String strOptString2 = jSONObject2.optString("freeTrialPeriod");
            Intrinsics.checkNotNullExpressionValue(strOptString2, "skuDetailsJSON.optString…GP_IAP_FREE_TRIAL_PERIOD)");
            AbstractC3559x2.a("fb_free_trial_period", strOptString2, bundle, qVar);
            String introductoryPriceCycles = jSONObject2.optString("introductoryPriceCycles");
            Intrinsics.checkNotNullExpressionValue(introductoryPriceCycles, "introductoryPriceCycles");
            if (introductoryPriceCycles.length() > 0) {
                AbstractC3559x2.a("fb_intro_price_cycles", introductoryPriceCycles, bundle, qVar);
            }
            String introductoryPricePeriod = jSONObject2.optString("introductoryPricePeriod");
            Intrinsics.checkNotNullExpressionValue(introductoryPricePeriod, "introductoryPricePeriod");
            if (introductoryPricePeriod.length() > 0) {
                AbstractC3559x2.a("fb_intro_period", introductoryPricePeriod, bundle, qVar);
            }
            String introductoryPriceAmountMicros = jSONObject2.optString("introductoryPriceAmountMicros");
            Intrinsics.checkNotNullExpressionValue(introductoryPriceAmountMicros, "introductoryPriceAmountMicros");
            if (introductoryPriceAmountMicros.length() > 0) {
                AbstractC3559x2.a("fb_intro_price_amount_micros", introductoryPriceAmountMicros, bundle, qVar);
            }
        }
        BigDecimal bigDecimal = new BigDecimal(jSONObject2.getLong("price_amount_micros") / 1000000.0d);
        Currency currency = Currency.getInstance(jSONObject2.getString("price_currency_code"));
        Intrinsics.checkNotNullExpressionValue(currency, "getInstance(skuDetailsJS…RICE_CURRENCY_CODE_V2V4))");
        return new i(bigDecimal, currency, bundle, qVar);
    }

    public static ArrayList b(String str, Bundle bundle, q qVar, JSONObject jSONObject) throws JSONException {
        if (!Intrinsics.b(str, "subs")) {
            JSONObject jSONObject2 = jSONObject.getJSONObject("oneTimePurchaseOfferDetails");
            if (jSONObject2 == null) {
                return null;
            }
            BigDecimal bigDecimal = new BigDecimal(jSONObject2.getLong("priceAmountMicros") / 1000000.0d);
            Currency currency = Currency.getInstance(jSONObject2.getString("priceCurrencyCode"));
            Intrinsics.checkNotNullExpressionValue(currency, "getInstance(oneTimePurch…RICE_CURRENCY_CODE_V5V7))");
            return B.k(new i(bigDecimal, currency, bundle, qVar));
        }
        ArrayList arrayList = new ArrayList();
        String str2 = "subscriptionOfferDetails";
        JSONArray jSONArray = jSONObject.getJSONArray("subscriptionOfferDetails");
        if (jSONArray == null) {
            return null;
        }
        int length = jSONArray.length();
        int i = 0;
        while (i < length) {
            JSONObject jSONObject3 = jSONObject.getJSONArray(str2).getJSONObject(i);
            if (jSONObject3 == null) {
                return null;
            }
            Bundle bundle2 = new Bundle(bundle);
            q qVar2 = new q();
            LinkedHashMap linkedHashMap = qVar.a;
            for (r rVar : linkedHashMap.keySet()) {
                Map map = (Map) linkedHashMap.get(rVar);
                if (map != null) {
                    for (String str3 : map.keySet()) {
                        String str4 = str2;
                        int i2 = length;
                        Object obj = map.get(str3);
                        if (obj != null) {
                            qVar2.a(rVar, str3, obj);
                        }
                        str2 = str4;
                        length = i2;
                    }
                }
            }
            String str5 = str2;
            int i3 = length;
            String basePlanId = jSONObject3.getString("basePlanId");
            Map map2 = q.b;
            Intrinsics.checkNotNullExpressionValue(basePlanId, "basePlanId");
            AbstractC3559x2.a("fb_iap_base_plan", basePlanId, bundle2, qVar2);
            JSONObject jSONObject4 = jSONObject3.getJSONArray("pricingPhases").getJSONObject(r5.length() - 1);
            if (jSONObject4 == null) {
                return null;
            }
            String strOptString = jSONObject4.optString("billingPeriod");
            Intrinsics.checkNotNullExpressionValue(strOptString, "subscriptionJSON.optStri…IOD\n                    )");
            AbstractC3559x2.a("fb_iap_subs_period", strOptString, bundle2, qVar2);
            if (!jSONObject4.has("recurrenceMode") || jSONObject4.getInt("recurrenceMode") == 3) {
                AbstractC3559x2.a("fb_iap_subs_auto_renewing", "false", bundle2, qVar2);
            } else {
                AbstractC3559x2.a("fb_iap_subs_auto_renewing", "true", bundle2, qVar2);
            }
            BigDecimal bigDecimal2 = new BigDecimal(jSONObject4.getLong("priceAmountMicros") / 1000000.0d);
            Currency currency2 = Currency.getInstance(jSONObject4.getString("priceCurrencyCode"));
            Intrinsics.checkNotNullExpressionValue(currency2, "getInstance(subscription…RICE_CURRENCY_CODE_V5V7))");
            arrayList.add(new i(bigDecimal2, currency2, bundle2, qVar2));
            i++;
            str2 = str5;
            length = i3;
        }
        return arrayList;
    }

    public static final boolean c() {
        v vVarB = y.b(o.b());
        return vVarB != null && com.facebook.B.c() && vVarB.f;
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x026d  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x02ca  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x0218 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:143:? A[ADDED_TO_REGION, RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:21:0x00dc A[Catch: Exception -> 0x0045, JSONException -> 0x0048, TryCatch #9 {JSONException -> 0x0048, Exception -> 0x0045, blocks: (B:6:0x0027, B:8:0x003d, B:13:0x004b, B:21:0x00dc, B:22:0x00e3, B:23:0x00eb, B:25:0x00f1, B:26:0x0109, B:28:0x0111, B:29:0x011e, B:31:0x0126, B:35:0x0131, B:19:0x00d6), top: B:135:0x0027 }] */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00f1 A[Catch: Exception -> 0x0045, JSONException -> 0x0048, LOOP:0: B:23:0x00eb->B:25:0x00f1, LOOP_END, TryCatch #9 {JSONException -> 0x0048, Exception -> 0x0045, blocks: (B:6:0x0027, B:8:0x003d, B:13:0x004b, B:21:0x00dc, B:22:0x00e3, B:23:0x00eb, B:25:0x00f1, B:26:0x0109, B:28:0x0111, B:29:0x011e, B:31:0x0126, B:35:0x0131, B:19:0x00d6), top: B:135:0x0027 }] */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0111 A[Catch: Exception -> 0x0045, JSONException -> 0x0048, TryCatch #9 {JSONException -> 0x0048, Exception -> 0x0045, blocks: (B:6:0x0027, B:8:0x003d, B:13:0x004b, B:21:0x00dc, B:22:0x00e3, B:23:0x00eb, B:25:0x00f1, B:26:0x0109, B:28:0x0111, B:29:0x011e, B:31:0x0126, B:35:0x0131, B:19:0x00d6), top: B:135:0x0027 }] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x011e A[Catch: Exception -> 0x0045, JSONException -> 0x0048, TryCatch #9 {JSONException -> 0x0048, Exception -> 0x0045, blocks: (B:6:0x0027, B:8:0x003d, B:13:0x004b, B:21:0x00dc, B:22:0x00e3, B:23:0x00eb, B:25:0x00f1, B:26:0x0109, B:28:0x0111, B:29:0x011e, B:31:0x0126, B:35:0x0131, B:19:0x00d6), top: B:135:0x0027 }] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0148  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x018d  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0190  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0192  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x020b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(java.lang.String r17, java.lang.String r18, boolean r19, com.facebook.appevents.iap.s r20, boolean r21) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 780
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.internal.j.d(java.lang.String, java.lang.String, boolean, com.facebook.appevents.iap.s, boolean):void");
    }
}
