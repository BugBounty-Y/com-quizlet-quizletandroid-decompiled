package com.facebook.appevents.restrictivedatafilter;

import android.util.Log;
import com.facebook.internal.J;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.facebook.o;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArraySet;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class b {
    public static boolean b;
    public static final b a = new b();
    public static final ArrayList c = new ArrayList();
    public static final CopyOnWriteArraySet d = new CopyOnWriteArraySet();

    public final String a(String str, String str2) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                try {
                    Iterator it2 = new ArrayList(c).iterator();
                    while (it2.hasNext()) {
                        a aVar = (a) it2.next();
                        if (aVar != null && Intrinsics.b(str, aVar.a)) {
                            for (String str3 : aVar.b.keySet()) {
                                if (Intrinsics.b(str2, str3)) {
                                    return (String) aVar.b.get(str3);
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    Log.w("com.facebook.appevents.restrictivedatafilter.b", "getMatchedRuleType failed", e);
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }

    public final void b() {
        String str;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            v vVarK = y.k(o.b(), false);
            if (vVarK != null && (str = vVarK.l) != null && str.length() != 0) {
                JSONObject jSONObject = new JSONObject(str);
                ArrayList arrayList = c;
                arrayList.clear();
                CopyOnWriteArraySet copyOnWriteArraySet = d;
                copyOnWriteArraySet.clear();
                Iterator<String> itKeys = jSONObject.keys();
                while (itKeys.hasNext()) {
                    String eventName = itKeys.next();
                    JSONObject jSONObject2 = jSONObject.getJSONObject(eventName);
                    if (jSONObject2 != null) {
                        JSONObject jSONObjectOptJSONObject = jSONObject2.optJSONObject("restrictive_param");
                        Intrinsics.checkNotNullExpressionValue(eventName, "key");
                        HashMap restrictiveParams = new HashMap();
                        Intrinsics.checkNotNullParameter(eventName, "eventName");
                        Intrinsics.checkNotNullParameter(restrictiveParams, "restrictiveParams");
                        a aVar = new a();
                        aVar.a = eventName;
                        aVar.b = restrictiveParams;
                        if (jSONObjectOptJSONObject != null) {
                            HashMap mapI = J.i(jSONObjectOptJSONObject);
                            Intrinsics.checkNotNullParameter(mapI, "<set-?>");
                            aVar.b = mapI;
                            arrayList.add(aVar);
                        }
                        if (jSONObject2.has("process_event_name")) {
                            copyOnWriteArraySet.add(eventName);
                        }
                    }
                }
            }
        } catch (Exception unused) {
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
