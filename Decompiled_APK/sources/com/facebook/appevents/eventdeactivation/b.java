package com.facebook.appevents.eventdeactivation;

import com.facebook.appevents.e;
import com.facebook.internal.J;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.facebook.o;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class b {
    public static boolean b;
    public static final b a = new b();
    public static final ArrayList c = new ArrayList();
    public static final HashSet d = new HashSet();

    public static final void b(ArrayList events) {
        if (com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(events, "events");
            if (b) {
                Iterator it2 = events.iterator();
                while (it2.hasNext()) {
                    if (d.contains(((e) it2.next()).e)) {
                        it2.remove();
                    }
                }
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(b.class, th);
        }
    }

    public final synchronized void a() {
        v vVarK;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            vVarK = y.k(o.b(), false);
        } catch (Exception unused) {
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return;
        }
        if (vVarK == null) {
            return;
        }
        String str = vVarK.l;
        if (str != null && str.length() > 0) {
            JSONObject jSONObject = new JSONObject(str);
            c.clear();
            Iterator<String> itKeys = jSONObject.keys();
            while (itKeys.hasNext()) {
                String key = itKeys.next();
                JSONObject jSONObject2 = jSONObject.getJSONObject(key);
                if (jSONObject2 != null) {
                    if (jSONObject2.optBoolean("is_deprecated_event")) {
                        HashSet hashSet = d;
                        Intrinsics.checkNotNullExpressionValue(key, "key");
                        hashSet.add(key);
                    } else {
                        JSONArray jSONArrayOptJSONArray = jSONObject2.optJSONArray("deprecated_param");
                        Intrinsics.checkNotNullExpressionValue(key, "key");
                        ArrayList deprecateParams = new ArrayList();
                        Intrinsics.checkNotNullParameter(key, "eventName");
                        Intrinsics.checkNotNullParameter(deprecateParams, "deprecateParams");
                        a aVar = new a();
                        aVar.a = key;
                        aVar.b = deprecateParams;
                        if (jSONArrayOptJSONArray != null) {
                            ArrayList arrayListG = J.g(jSONArrayOptJSONArray);
                            Intrinsics.checkNotNullParameter(arrayListG, "<set-?>");
                            aVar.b = arrayListG;
                        }
                        c.add(aVar);
                    }
                }
            }
        }
    }
}
