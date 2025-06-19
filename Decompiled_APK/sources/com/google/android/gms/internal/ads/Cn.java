package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Cn {
    public final HashMap a = new HashMap();
    public final HashMap b = new HashMap();
    public final HashMap c = new HashMap();
    public final HashMap d = new HashMap();
    public final HashMap e = new HashMap();
    public final Xv f;
    public JSONObject g;

    public Cn(Xv xv) {
        this.f = xv;
    }

    public static final Bundle i(JSONObject jSONObject) {
        Bundle bundle = new Bundle();
        if (jSONObject != null) {
            Iterator<String> itKeys = jSONObject.keys();
            while (itKeys.hasNext()) {
                String next = itKeys.next();
                bundle.putString(next, jSONObject.optString(next, ""));
            }
        }
        return bundle;
    }

    public final synchronized Gu a(String str, String str2) {
        Map map;
        try {
            if (!TextUtils.isEmpty(str) && !TextUtils.isEmpty(str2) && !TextUtils.isEmpty(com.google.android.gms.ads.internal.j.C.h.d().n().e) && (map = (Map) this.c.get(str)) != null) {
                List<Dn> list = (List) map.get(str2);
                if (list == null) {
                    String strH = LA.h(this.g, str2, str);
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ta)).booleanValue()) {
                        strH = strH.toLowerCase(Locale.ROOT);
                    }
                    list = (List) map.get(strH);
                }
                if (list != null) {
                    HashMap map2 = new HashMap();
                    for (Dn dn : list) {
                        String str3 = dn.a;
                        if (!map2.containsKey(str3)) {
                            map2.put(str3, new ArrayList());
                        }
                        ((List) map2.get(str3)).add(dn.b);
                    }
                    return Gu.a(map2);
                }
            }
            return Gu.g;
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void b(String str) {
        if (!TextUtils.isEmpty(str)) {
            HashMap map = this.a;
            if (!map.containsKey(str)) {
                map.put(str, new Dn(new Bundle(), str));
            }
        }
    }

    public final synchronized Gu c(String str) {
        HashMap map;
        try {
            if (!TextUtils.isEmpty(str) && !TextUtils.isEmpty(com.google.android.gms.ads.internal.j.C.h.d().n().e)) {
                C2601s7 c2601s7 = AbstractC2773w7.o3;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                boolean zMatches = Pattern.matches((String) rVar.c.a(c2601s7), str);
                boolean zMatches2 = Pattern.matches((String) rVar.c.a(AbstractC2773w7.p3), str);
                if (zMatches) {
                    map = new HashMap(this.e);
                } else if (zMatches2) {
                    map = new HashMap(this.d);
                }
                return Gu.a(map);
            }
            return Gu.g;
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized ArrayList d(JSONObject jSONObject) {
        ArrayList arrayList;
        try {
            arrayList = new ArrayList();
            if (jSONObject != null) {
                Bundle bundleI = i(jSONObject.optJSONObject("data"));
                JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("rtb_adapters");
                if (jSONArrayOptJSONArray != null) {
                    ArrayList arrayList2 = new ArrayList();
                    for (int i = 0; i < jSONArrayOptJSONArray.length(); i++) {
                        String strOptString = jSONArrayOptJSONArray.optString(i, "");
                        if (!TextUtils.isEmpty(strOptString)) {
                            arrayList2.add(strOptString);
                        }
                    }
                    int size = arrayList2.size();
                    for (int i2 = 0; i2 < size; i2++) {
                        String str = (String) arrayList2.get(i2);
                        b(str);
                        if (((Dn) this.a.get(str)) != null) {
                            arrayList.add(new Dn(bundleI, str));
                        }
                    }
                }
            }
        } finally {
        }
        return arrayList;
    }

    public final synchronized void e() {
        JSONObject jSONObject;
        try {
            if (!((Boolean) AbstractC1955d8.b.o()).booleanValue()) {
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.P1)).booleanValue() && (jSONObject = com.google.android.gms.ads.internal.j.C.h.d().n().g) != null) {
                    try {
                        JSONArray jSONArray = jSONObject.getJSONArray("adapter_settings");
                        for (int i = 0; i < jSONArray.length(); i++) {
                            JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                            String strOptString = jSONObject2.optString("adapter_class_name");
                            JSONArray jSONArrayOptJSONArray = jSONObject2.optJSONArray("permission_set");
                            if (!TextUtils.isEmpty(strOptString) && jSONArrayOptJSONArray != null) {
                                for (int i2 = 0; i2 < jSONArrayOptJSONArray.length(); i2++) {
                                    JSONObject jSONObject3 = jSONArrayOptJSONArray.getJSONObject(i2);
                                    boolean zOptBoolean = jSONObject3.optBoolean("enable_rendering", false);
                                    boolean zOptBoolean2 = jSONObject3.optBoolean("collect_secure_signals", false);
                                    boolean zOptBoolean3 = jSONObject3.optBoolean("collect_secure_signals_on_full_app", false);
                                    String strOptString2 = jSONObject3.optString("platform");
                                    Fn fn = new Fn(strOptString, zOptBoolean2, zOptBoolean, zOptBoolean3, new Bundle());
                                    if (strOptString2.equals("ADMOB")) {
                                        this.d.put(strOptString, fn);
                                    } else if (strOptString2.equals("AD_MANAGER")) {
                                        this.e.put(strOptString, fn);
                                    }
                                }
                            }
                        }
                    } catch (JSONException unused) {
                        com.google.android.gms.ads.internal.util.A.m();
                    }
                }
            }
        } finally {
        }
    }

    public final synchronized void f(String str, String str2, ArrayList arrayList) {
        try {
            if (TextUtils.isEmpty(str) || TextUtils.isEmpty(str2)) {
                return;
            }
            HashMap map = this.c;
            Map map2 = (Map) map.get(str);
            if (map2 == null) {
                map2 = new HashMap();
            }
            map.put(str, map2);
            List arrayList2 = (List) map2.get(str2);
            if (arrayList2 == null) {
                arrayList2 = new ArrayList();
            }
            arrayList2.addAll(arrayList);
            map2.put(str2, arrayList2);
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void g() {
        JSONArray jSONArrayOptJSONArray;
        try {
            JSONObject jSONObject = com.google.android.gms.ads.internal.j.C.h.d().n().g;
            if (jSONObject != null) {
                try {
                    JSONArray jSONArrayOptJSONArray2 = jSONObject.optJSONArray("ad_unit_id_settings");
                    this.g = jSONObject.optJSONObject("ad_unit_patterns");
                    if (jSONArrayOptJSONArray2 != null) {
                        for (int i = 0; i < jSONArrayOptJSONArray2.length(); i++) {
                            JSONObject jSONObject2 = jSONArrayOptJSONArray2.getJSONObject(i);
                            String lowerCase = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ta)).booleanValue() ? jSONObject2.optString("ad_unit_id", "").toLowerCase(Locale.ROOT) : jSONObject2.optString("ad_unit_id", "");
                            String strOptString = jSONObject2.optString("format", "");
                            ArrayList arrayList = new ArrayList();
                            JSONObject jSONObjectOptJSONObject = jSONObject2.optJSONObject("mediation_config");
                            if (jSONObjectOptJSONObject != null && (jSONArrayOptJSONArray = jSONObjectOptJSONObject.optJSONArray("ad_networks")) != null) {
                                for (int i2 = 0; i2 < jSONArrayOptJSONArray.length(); i2++) {
                                    arrayList.addAll(d(jSONArrayOptJSONArray.getJSONObject(i2)));
                                }
                            }
                            f(strOptString, lowerCase, arrayList);
                        }
                    }
                } catch (JSONException unused) {
                    com.google.android.gms.ads.internal.util.A.m();
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void h() {
        JSONObject jSONObject;
        if (!((Boolean) AbstractC1955d8.e.o()).booleanValue()) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.O1)).booleanValue() && (jSONObject = com.google.android.gms.ads.internal.j.C.h.d().n().g) != null) {
                try {
                    JSONArray jSONArray = jSONObject.getJSONArray("signal_adapters");
                    for (int i = 0; i < jSONArray.length(); i++) {
                        JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                        Bundle bundleI = i(jSONObject2.optJSONObject("data"));
                        String strOptString = jSONObject2.optString("adapter_class_name");
                        boolean zOptBoolean = jSONObject2.optBoolean("render", false);
                        boolean zOptBoolean2 = jSONObject2.optBoolean("collect_signals", false);
                        if (!TextUtils.isEmpty(strOptString)) {
                            this.b.put(strOptString, new Fn(strOptString, zOptBoolean2, zOptBoolean, true, bundleI));
                        }
                    }
                } catch (JSONException unused) {
                    com.google.android.gms.ads.internal.util.A.m();
                }
            }
        }
    }
}
