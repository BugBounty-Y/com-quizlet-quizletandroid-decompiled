package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.ua, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2696ua {
    public final List a;

    public C2696ua(JSONObject jSONObject) throws JSONException {
        if (com.google.android.gms.ads.internal.util.client.i.k(2)) {
            com.google.android.gms.ads.internal.util.A.l("Mediation Response JSON: ".concat(String.valueOf(jSONObject.toString(2))));
        }
        JSONArray jSONArray = jSONObject.getJSONArray("ad_networks");
        ArrayList arrayList = new ArrayList(jSONArray.length());
        int i = -1;
        for (int i2 = 0; i2 < jSONArray.length(); i2++) {
            try {
                C2653ta c2653ta = new C2653ta(jSONArray.getJSONObject(i2));
                com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_BANNER.equalsIgnoreCase(c2653ta.c);
                arrayList.add(c2653ta);
                if (i < 0) {
                    Iterator it2 = c2653ta.a.iterator();
                    while (true) {
                        if (it2.hasNext()) {
                            if (((String) it2.next()).equals("com.google.ads.mediation.admob.AdMobAdapter")) {
                                i = i2;
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            } catch (JSONException unused) {
            }
        }
        jSONArray.length();
        this.a = Collections.unmodifiableList(arrayList);
        jSONObject.optString("qdata");
        jSONObject.optInt("fs_model_type", -1);
        jSONObject.optLong("timeout_ms", -1L);
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("settings");
        if (jSONObjectOptJSONObject != null) {
            jSONObjectOptJSONObject.optLong("ad_network_timeout_millis", -1L);
            L9 l9 = com.google.android.gms.ads.internal.j.C.v;
            L9.h("click_urls", jSONObjectOptJSONObject);
            L9.h("imp_urls", jSONObjectOptJSONObject);
            L9.h("downloaded_imp_urls", jSONObjectOptJSONObject);
            L9.h("nofill_urls", jSONObjectOptJSONObject);
            L9.h("remote_ping_urls", jSONObjectOptJSONObject);
            jSONObjectOptJSONObject.optBoolean("render_in_browser", false);
            jSONObjectOptJSONObject.optLong("refresh", -1L);
            zzbwj.a(jSONObjectOptJSONObject.optJSONArray("rewards"));
            jSONObjectOptJSONObject.optBoolean("use_displayed_impression", false);
            jSONObjectOptJSONObject.optBoolean("allow_pub_rendered_attribution", false);
            jSONObjectOptJSONObject.optBoolean("allow_pub_owned_ad_view", false);
            jSONObjectOptJSONObject.optBoolean("allow_custom_click_gesture", false);
        }
    }
}
