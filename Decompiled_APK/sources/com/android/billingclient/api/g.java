package com.android.billingclient.api;

import org.json.JSONObject;

/* loaded from: classes.dex */
public final class g {
    public final long a;
    public final String b;
    public final String c;

    public g(JSONObject jSONObject) {
        this.c = jSONObject.optString("billingPeriod");
        this.b = jSONObject.optString("priceCurrencyCode");
        jSONObject.optString("formattedPrice");
        this.a = jSONObject.optLong("priceAmountMicros");
        jSONObject.optInt("recurrenceMode");
        jSONObject.optInt("billingCycleCount");
    }
}
