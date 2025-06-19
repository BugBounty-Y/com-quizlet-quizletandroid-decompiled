package com.facebook.appevents.integrity;

import com.facebook.internal.J;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.facebook.o;
import java.util.HashMap;
import java.util.HashSet;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class g {
    public static boolean b;
    public static final g a = new g();
    public static HashMap c = new HashMap();

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
                c = new HashMap();
                JSONArray jSONArray = vVarK.p;
                if (jSONArray == null || jSONArray.length() == 0) {
                    return;
                }
                int length = jSONArray.length();
                for (int i = 0; i < length; i++) {
                    JSONObject jSONObject = jSONArray.getJSONObject(i);
                    boolean zHas = jSONObject.has("key");
                    boolean zHas2 = jSONObject.has("value");
                    if (zHas && zHas2) {
                        String string = jSONObject.getString("key");
                        JSONArray jSONArray2 = jSONObject.getJSONArray("value");
                        if (string != null && (hashSetF = J.f(jSONArray2)) != null) {
                            c.put(string, hashSetF);
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
