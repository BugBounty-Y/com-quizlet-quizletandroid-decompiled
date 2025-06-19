package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.Arrays;
import java.util.List;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Zb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1810Zb {
    public final List a;
    public final String b;
    public final String c;
    public final boolean d;
    public final boolean e;
    public final String f;
    public final int g;
    public final JSONObject h;
    public final String i;
    public final long j;
    public final long k;

    public C1810Zb(JSONObject jSONObject) throws NumberFormatException {
        this.f = jSONObject.optString(DTBMetricsConfiguration.APSMETRICS_URL);
        this.b = jSONObject.optString("base_uri");
        this.c = jSONObject.optString("post_parameters");
        String strOptString = jSONObject.optString("drt_include");
        this.d = strOptString != null && (strOptString.equals("1") || strOptString.equals("true"));
        String strOptString2 = jSONObject.optString("cookies_include", "true");
        this.e = strOptString2 != null && (strOptString2.equals("1") || strOptString2.equals("true"));
        jSONObject.optString("request_id");
        jSONObject.optString(DBUserFields.Names.USER_UPGRADE_TYPE);
        String strOptString3 = jSONObject.optString("errors");
        this.a = strOptString3 == null ? null : Arrays.asList(strOptString3.split(","));
        this.g = jSONObject.optInt("valid", 0) == 1 ? -2 : 1;
        jSONObject.optString("fetched_ad");
        jSONObject.optBoolean("render_test_ad_label");
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("preprocessor_flags");
        this.h = jSONObjectOptJSONObject == null ? new JSONObject() : jSONObjectOptJSONObject;
        jSONObject.optString("analytics_query_ad_event_id");
        jSONObject.optBoolean("is_analytics_logging_enabled");
        this.i = jSONObject.optString("pool_key");
        String strOptString4 = jSONObject.optString("start_time");
        Long lValueOf = -1L;
        if (!TextUtils.isEmpty(strOptString4)) {
            try {
                lValueOf = Long.valueOf(strOptString4);
            } catch (NumberFormatException unused) {
            }
        }
        this.j = lValueOf.longValue();
        String strOptString5 = jSONObject.optString("end_time");
        Long lValueOf2 = -1L;
        if (!TextUtils.isEmpty(strOptString5)) {
            try {
                lValueOf2 = Long.valueOf(strOptString5);
            } catch (NumberFormatException unused2) {
            }
        }
        this.k = lValueOf2.longValue();
    }
}
