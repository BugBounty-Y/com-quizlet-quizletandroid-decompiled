package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import com.amazon.device.ads.DTBAdSize;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.cd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1923cd {
    public String d;
    public String e;
    public long f;
    public JSONObject g;
    public boolean h;
    public boolean j;
    public final ArrayList a = new ArrayList();
    public final ArrayList b = new ArrayList();
    public final HashMap c = new HashMap();
    public final ArrayList i = new ArrayList();

    public C1923cd(String str, long j) throws JSONException {
        JSONObject jSONObjectOptJSONObject;
        JSONObject jSONObjectOptJSONObject2;
        JSONArray jSONArrayOptJSONArray;
        JSONObject jSONObjectOptJSONObject3;
        this.d = "";
        this.h = false;
        this.j = false;
        this.e = str;
        this.f = j;
        if (TextUtils.isEmpty(str)) {
            return;
        }
        try {
            this.g = new JSONObject(str);
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Fb)).booleanValue() && a()) {
                return;
            }
            if (this.g.optInt("status", -1) != 1) {
                this.h = false;
                com.google.android.gms.ads.internal.util.client.i.h("App settings could not be fetched successfully.");
                return;
            }
            this.h = true;
            this.d = this.g.optString("app_id");
            JSONArray jSONArrayOptJSONArray2 = this.g.optJSONArray("ad_unit_id_settings");
            if (jSONArrayOptJSONArray2 != null) {
                for (int i = 0; i < jSONArrayOptJSONArray2.length(); i++) {
                    JSONObject jSONObject = jSONArrayOptJSONArray2.getJSONObject(i);
                    String strOptString = jSONObject.optString("format");
                    String strOptString2 = jSONObject.optString("ad_unit_id");
                    if (!TextUtils.isEmpty(strOptString) && !TextUtils.isEmpty(strOptString2)) {
                        if (DTBAdSize.AAX_INTERSTITIAL_AD_SIZE.equalsIgnoreCase(strOptString)) {
                            this.b.add(strOptString2);
                        } else if (("rewarded".equalsIgnoreCase(strOptString) || "rewarded_interstitial".equals(strOptString)) && (jSONObjectOptJSONObject3 = jSONObject.optJSONObject("mediation_config")) != null) {
                            this.c.put(strOptString2, new C2696ua(jSONObjectOptJSONObject3));
                        }
                    }
                }
            }
            JSONArray jSONArrayOptJSONArray3 = this.g.optJSONArray("persistable_banner_ad_unit_ids");
            if (jSONArrayOptJSONArray3 != null) {
                for (int i2 = 0; i2 < jSONArrayOptJSONArray3.length(); i2++) {
                    this.a.add(jSONArrayOptJSONArray3.optString(i2));
                }
            }
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.N6)).booleanValue() && (jSONObjectOptJSONObject2 = this.g.optJSONObject("common_settings")) != null && (jSONArrayOptJSONArray = jSONObjectOptJSONObject2.optJSONArray("loeid")) != null) {
                for (int i3 = 0; i3 < jSONArrayOptJSONArray.length(); i3++) {
                    this.i.add(jSONArrayOptJSONArray.get(i3).toString());
                }
            }
            if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.j6)).booleanValue() || (jSONObjectOptJSONObject = this.g.optJSONObject("common_settings")) == null) {
                return;
            }
            this.j = jSONObjectOptJSONObject.optBoolean("is_prefetching_enabled", false);
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Exception occurred while processing app setting json", e);
            com.google.android.gms.ads.internal.j.C.h.h("AppSettings.parseAppSettingsJson", e);
        }
    }

    public final boolean a() {
        if (!TextUtils.isEmpty(this.e) && this.g != null) {
            C2601s7 c2601s7 = AbstractC2773w7.Ib;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            long jLongValue = ((Long) rVar.c.a(c2601s7)).longValue();
            C2601s7 c2601s72 = AbstractC2773w7.Hb;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue() && !TextUtils.isEmpty(this.e)) {
                jLongValue = this.g.optLong("cache_ttl_sec", ((Long) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s7)).longValue());
            }
            com.google.android.gms.ads.internal.j.C.k.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            if (jLongValue >= 0) {
                long j = this.f;
                if (j > jCurrentTimeMillis || TimeUnit.MILLISECONDS.toSeconds(jCurrentTimeMillis - j) > jLongValue) {
                    this.a.clear();
                    this.b.clear();
                    this.c.clear();
                    this.d = "";
                    this.e = "";
                    this.g = null;
                    this.h = false;
                    this.i.clear();
                    this.j = false;
                    return true;
                }
            }
        }
        return false;
    }
}
