package com.facebook.internal;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import androidx.compose.animation.d0;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class y {
    public static final y a = new y();
    public static final List b = kotlin.collections.B.j("supports_implicit_sdk_logging", "gdpv4_nux_content", "gdpv4_nux_enabled", "android_dialog_configs", "android_sdk_error_categories", "app_events_session_timeout", "app_events_feature_bitmask", "auto_event_mapping_android", "seamless_login", "smart_login_bookmark_icon_url", "smart_login_menu_icon_url", "restrictive_data_filter_params", "aam_rules", "suggested_events_setting", "protected_mode_rules", "auto_log_app_events_default", "auto_log_app_events_enabled", d0.r(new StringBuilder("app_events_config.os_version("), Build.VERSION.RELEASE, ')'));
    public static final ConcurrentHashMap c = new ConcurrentHashMap();
    public static final AtomicReference d = new AtomicReference(x.a);
    public static final ConcurrentLinkedQueue e = new ConcurrentLinkedQueue();
    public static boolean f;

    public static JSONObject a() {
        Bundle bundle = new Bundle();
        ArrayList arrayList = new ArrayList();
        arrayList.addAll(b);
        bundle.putString("fields", TextUtils.join(",", arrayList));
        String str = com.facebook.t.j;
        com.facebook.t tVarQ = assistantMode.utils.studiableMetadata.b.Q(null, "app", null);
        tVarQ.i = true;
        Intrinsics.checkNotNullParameter(bundle, "<set-?>");
        tVarQ.d = bundle;
        JSONObject jSONObject = tVarQ.c().d;
        return jSONObject == null ? new JSONObject() : jSONObject;
    }

    public static final v b(String str) {
        return (v) c.get(str);
    }

    public static final HashMap c() {
        JSONObject jSONObject;
        String string = com.facebook.o.a().getSharedPreferences("com.facebook.internal.preferences.APP_SETTINGS", 0).getString(d0.s(new Object[]{com.facebook.o.b()}, 1, "com.facebook.internal.APP_SETTINGS.%s", "format(format, *args)"), null);
        if (!J.D(string)) {
            if (string == null) {
                throw new IllegalStateException("Required value was null.");
            }
            try {
                jSONObject = new JSONObject(string);
            } catch (JSONException unused) {
                com.facebook.o oVar = com.facebook.o.a;
                jSONObject = null;
            }
            if (jSONObject != null) {
                return h(jSONObject);
            }
        }
        return null;
    }

    public static final void d() {
        Context contextA = com.facebook.o.a();
        String strB = com.facebook.o.b();
        boolean zD = J.D(strB);
        x xVar = x.d;
        y yVar = a;
        AtomicReference atomicReference = d;
        if (zD) {
            atomicReference.set(xVar);
            yVar.j();
            return;
        }
        if (c.containsKey(strB)) {
            atomicReference.set(x.c);
            yVar.j();
            return;
        }
        x xVar2 = x.a;
        x xVar3 = x.b;
        while (true) {
            if (atomicReference.compareAndSet(xVar2, xVar3)) {
                break;
            }
            if (atomicReference.get() != xVar2) {
                while (!atomicReference.compareAndSet(xVar, xVar3)) {
                    if (atomicReference.get() != xVar) {
                        yVar.j();
                        return;
                    }
                }
            }
        }
        com.facebook.o.c().execute(new t(contextA, d0.s(new Object[]{strB}, 1, "com.facebook.internal.APP_SETTINGS.%s", "format(format, *args)"), strB));
    }

    /* JADX WARN: Removed duplicated region for block: B:56:0x0169  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.facebook.internal.v e(java.lang.String r49, org.json.JSONObject r50) throws org.json.JSONException, java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 736
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.internal.y.e(java.lang.String, org.json.JSONObject):com.facebook.internal.v");
    }

    public static ArrayList f(String str, JSONObject jSONObject) throws JSONException {
        JSONArray jSONArray;
        if (jSONObject != null) {
            try {
                jSONArray = jSONObject.getJSONArray("iap_manual_and_auto_log_dedup_keys");
            } catch (Exception unused) {
            }
        } else {
            jSONArray = null;
        }
        if (jSONArray != null) {
            int length = jSONArray.length();
            for (int i = 0; i < length; i++) {
                JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                if (Intrinsics.b(jSONObject2.getString("key"), "prod_keys")) {
                    JSONArray jSONArray2 = jSONObject2.getJSONArray("value");
                    int length2 = jSONArray2.length();
                    for (int i2 = 0; i2 < length2; i2++) {
                        JSONObject jSONObject3 = jSONArray2.getJSONObject(i2);
                        if (Intrinsics.b(jSONObject3.getString("key"), str)) {
                            JSONArray jSONArray3 = jSONObject3.getJSONArray("value");
                            ArrayList arrayList = new ArrayList();
                            int length3 = jSONArray3.length();
                            for (int i3 = 0; i3 < length3; i3++) {
                                arrayList.add(jSONArray3.getJSONObject(i3).getString("value"));
                            }
                            ArrayList arrayList2 = new ArrayList();
                            arrayList2.addAll(arrayList);
                            return arrayList2;
                        }
                    }
                }
            }
        }
        return null;
    }

    public static ArrayList g(JSONObject jSONObject, boolean z) throws JSONException {
        JSONArray jSONArray;
        if (jSONObject != null) {
            try {
                jSONArray = jSONObject.getJSONArray("iap_manual_and_auto_log_dedup_keys");
            } catch (Exception unused) {
            }
        } else {
            jSONArray = null;
        }
        if (jSONArray == null) {
            return null;
        }
        int length = jSONArray.length();
        ArrayList arrayList = null;
        for (int i = 0; i < length; i++) {
            JSONObject jSONObject2 = jSONArray.getJSONObject(i);
            String string = jSONObject2.getString("key");
            if ((!Intrinsics.b(string, "prod_keys") || !z) && (!Intrinsics.b(string, "test_keys") || z)) {
                JSONArray jSONArray2 = jSONObject2.getJSONArray("value");
                int length2 = jSONArray2.length();
                for (int i2 = 0; i2 < length2; i2++) {
                    JSONObject jSONObject3 = jSONArray2.getJSONObject(i2);
                    String string2 = jSONObject3.getString("key");
                    if (!Intrinsics.b(string2, "_valueToSum") && !Intrinsics.b(string2, "fb_currency")) {
                        JSONArray jSONArray3 = jSONObject3.getJSONArray("value");
                        ArrayList arrayList2 = new ArrayList();
                        int length3 = jSONArray3.length();
                        for (int i3 = 0; i3 < length3; i3++) {
                            try {
                                arrayList2.add(jSONArray3.getJSONObject(i3).getString("value"));
                            } catch (Exception unused2) {
                                return null;
                            }
                        }
                        if (arrayList == null) {
                            arrayList = new ArrayList();
                        }
                        arrayList.add(new Pair(string2, arrayList2));
                    }
                }
            }
        }
        return arrayList;
    }

    public static HashMap h(JSONObject jSONObject) {
        HashMap map = new HashMap();
        if (!jSONObject.isNull("auto_log_app_events_default")) {
            try {
                map.put("auto_log_app_events_default", Boolean.valueOf(jSONObject.getBoolean("auto_log_app_events_default")));
            } catch (JSONException unused) {
                com.facebook.o oVar = com.facebook.o.a;
            }
        }
        if (!jSONObject.isNull("auto_log_app_events_enabled")) {
            try {
                map.put("auto_log_app_events_enabled", Boolean.valueOf(jSONObject.getBoolean("auto_log_app_events_enabled")));
            } catch (JSONException unused2) {
                com.facebook.o oVar2 = com.facebook.o.a;
            }
        }
        if (map.isEmpty()) {
            return null;
        }
        return map;
    }

    public static JSONArray i(String str, JSONObject jSONObject) {
        if (jSONObject != null) {
            return jSONObject.optJSONArray(str);
        }
        return null;
    }

    public static final v k(String applicationId, boolean z) {
        Intrinsics.checkNotNullParameter(applicationId, "applicationId");
        if (!z) {
            ConcurrentHashMap concurrentHashMap = c;
            if (concurrentHashMap.containsKey(applicationId)) {
                return (v) concurrentHashMap.get(applicationId);
            }
        }
        y yVar = a;
        v vVarE = e(applicationId, a());
        if (applicationId.equals(com.facebook.o.b())) {
            d.set(x.c);
            yVar.j();
        }
        return vVarE;
    }

    public final synchronized void j() {
        x xVar = (x) d.get();
        if (x.a != xVar && x.b != xVar) {
            v vVar = (v) c.get(com.facebook.o.b());
            Handler handler = new Handler(Looper.getMainLooper());
            if (x.d == xVar) {
                while (true) {
                    ConcurrentLinkedQueue concurrentLinkedQueue = e;
                    if (concurrentLinkedQueue.isEmpty()) {
                        return;
                    } else {
                        handler.post(new w((com.facebook.appevents.l) concurrentLinkedQueue.poll()));
                    }
                }
            } else {
                while (true) {
                    ConcurrentLinkedQueue concurrentLinkedQueue2 = e;
                    if (concurrentLinkedQueue2.isEmpty()) {
                        return;
                    } else {
                        handler.post(new w((com.facebook.appevents.l) concurrentLinkedQueue2.poll(), vVar));
                    }
                }
            }
        }
    }
}
