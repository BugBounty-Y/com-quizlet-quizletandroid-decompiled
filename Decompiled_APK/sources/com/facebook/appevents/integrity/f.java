package com.facebook.appevents.integrity;

import android.os.Bundle;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.facebook.o;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;
import org.json.JSONArray;

/* loaded from: classes.dex */
public final class f {
    public static boolean b;
    public static HashSet d;
    public static final f a = new f();
    public static final u c = l.b(e.a);

    public static final void b(Bundle bundle) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return;
        }
        try {
            if (b && bundle != null && !bundle.isEmpty() && d != null) {
                ArrayList arrayList = new ArrayList();
                Set<String> setKeySet = bundle.keySet();
                Intrinsics.checkNotNullExpressionValue(setKeySet, "parameters.keySet()");
                for (String param : setKeySet) {
                    HashSet hashSet = d;
                    Intrinsics.d(hashSet);
                    if (!hashSet.contains(param)) {
                        Intrinsics.checkNotNullExpressionValue(param, "param");
                        arrayList.add(param);
                    }
                }
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    bundle.remove((String) it2.next());
                }
                bundle.putString("pm", "1");
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
        }
    }

    public final void a() {
        HashSet hashSet;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            v vVarK = y.k(o.b(), false);
            if (vVarK == null) {
                return;
            }
            JSONArray jSONArray = vVarK.m;
            HashSet hashSet2 = null;
            if (com.facebook.internal.instrument.crashshield.a.b(this) || jSONArray == null) {
                hashSet = null;
            } else {
                try {
                } catch (Throwable th) {
                    com.facebook.internal.instrument.crashshield.a.a(this, th);
                }
                if (jSONArray.length() == 0) {
                    hashSet = null;
                } else {
                    hashSet = new HashSet();
                    int length = jSONArray.length();
                    for (int i = 0; i < length; i++) {
                        String string = jSONArray.getString(i);
                        Intrinsics.checkNotNullExpressionValue(string, "jsonArray.getString(i)");
                        hashSet.add(string);
                    }
                }
            }
            if (hashSet == null) {
                if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                    try {
                        hashSet2 = (HashSet) c.getValue();
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(this, th2);
                    }
                }
                hashSet = hashSet2;
            }
            d = hashSet;
        } catch (Throwable th3) {
            com.facebook.internal.instrument.crashshield.a.a(this, th3);
        }
    }

    public final boolean c(Bundle bundle) {
        if (com.facebook.internal.instrument.crashshield.a.b(this) || bundle == null) {
            return false;
        }
        try {
            if (bundle.containsKey("pm")) {
                if (Intrinsics.b(bundle.get("pm"), "1")) {
                    return true;
                }
            }
            return false;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return false;
        }
    }
}
