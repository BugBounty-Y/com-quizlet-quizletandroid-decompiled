package com.facebook.appevents.integrity;

import android.os.Bundle;
import com.facebook.internal.J;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.facebook.o;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class h {
    public static boolean b;
    public static final h a = new h();
    public static HashSet c = new HashSet();
    public static HashMap d = new HashMap();

    public static final void b(Bundle bundle, String eventName) {
        if (com.facebook.internal.instrument.crashshield.a.b(h.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(eventName, "eventName");
            if (b && bundle != null) {
                if (!c.isEmpty() || d.containsKey(eventName)) {
                    JSONArray jSONArray = new JSONArray();
                    try {
                        HashSet hashSet = (HashSet) d.get(eventName);
                        Iterator it2 = new ArrayList(bundle.keySet()).iterator();
                        while (it2.hasNext()) {
                            String key = (String) it2.next();
                            h hVar = a;
                            Intrinsics.checkNotNullExpressionValue(key, "key");
                            if (!com.facebook.internal.instrument.crashshield.a.b(hVar)) {
                                try {
                                    if (c.contains(key) || (hashSet != null && !hashSet.isEmpty() && hashSet.contains(key))) {
                                        bundle.remove(key);
                                        jSONArray.put(key);
                                    }
                                } catch (Throwable th) {
                                    com.facebook.internal.instrument.crashshield.a.a(hVar, th);
                                }
                            }
                        }
                    } catch (Exception unused) {
                    }
                    if (jSONArray.length() > 0) {
                        bundle.putString("_filteredKey", jSONArray.toString());
                    }
                }
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(h.class, th2);
        }
    }

    public final void a() {
        HashSet hashSetF;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            v vVarK = y.k(o.b(), false);
            if (vVarK == null) {
                return;
            }
            try {
                c = new HashSet();
                d = new HashMap();
                JSONArray jSONArray = vVarK.q;
                if (jSONArray == null || jSONArray.length() == 0) {
                    return;
                }
                int length = jSONArray.length();
                for (int i = 0; i < length; i++) {
                    JSONObject jSONObject = jSONArray.getJSONObject(i);
                    boolean zHas = jSONObject.has("key");
                    boolean zHas2 = jSONObject.has("value");
                    if (zHas && zHas2) {
                        String sensitiveParamsScope = jSONObject.getString("key");
                        JSONArray jSONArray2 = jSONObject.getJSONArray("value");
                        if (jSONArray2 != null && (hashSetF = J.f(jSONArray2)) != null) {
                            if (sensitiveParamsScope.equals("_MTSDK_Default_")) {
                                c = hashSetF;
                            } else {
                                HashMap map = d;
                                Intrinsics.checkNotNullExpressionValue(sensitiveParamsScope, "sensitiveParamsScope");
                                map.put(sensitiveParamsScope, hashSetF);
                            }
                        }
                    }
                }
            } catch (Exception unused) {
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
