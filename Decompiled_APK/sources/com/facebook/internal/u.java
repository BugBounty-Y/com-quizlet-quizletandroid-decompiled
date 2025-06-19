package com.facebook.internal;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import androidx.compose.animation.d0;
import com.amazon.device.ads.DtbConstants;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class u {
    public static final AtomicBoolean a;
    public static final ConcurrentLinkedQueue b;
    public static final ConcurrentHashMap c;
    public static Long d;
    public static androidx.appcompat.app.Q e;

    static {
        kotlin.jvm.internal.K.a(u.class).f();
        a = new AtomicBoolean(false);
        b = new ConcurrentLinkedQueue();
        c = new ConcurrentHashMap();
    }

    public static JSONObject a() {
        Bundle bundle = new Bundle();
        bundle.putString("platform", DtbConstants.NATIVE_OS_NAME);
        com.facebook.o oVar = com.facebook.o.a;
        bundle.putString("sdk_version", "18.0.3");
        bundle.putString("fields", "gatekeepers");
        String str = com.facebook.t.j;
        com.facebook.t tVarQ = assistantMode.utils.studiableMetadata.b.Q(null, d0.s(new Object[]{"mobile_sdk_gk"}, 1, "app/%s", "format(format, *args)"), null);
        Intrinsics.checkNotNullParameter(bundle, "<set-?>");
        tVarQ.d = bundle;
        JSONObject jSONObject = tVarQ.c().d;
        return jSONObject == null ? new JSONObject() : jSONObject;
    }

    public static final boolean b(String name, String appId, boolean z) {
        HashMap map;
        Boolean bool;
        Intrinsics.checkNotNullParameter(name, "name");
        ArrayList<com.facebook.internal.gatekeeper.a> arrayList = null;
        c(null);
        ConcurrentHashMap concurrentHashMap = c;
        if (concurrentHashMap.containsKey(appId)) {
            androidx.appcompat.app.Q q = e;
            if (q != null) {
                Intrinsics.checkNotNullParameter(appId, "appId");
                ConcurrentHashMap concurrentHashMap2 = (ConcurrentHashMap) ((ConcurrentHashMap) q.a).get(appId);
                if (concurrentHashMap2 != null) {
                    arrayList = new ArrayList(concurrentHashMap2.size());
                    Iterator it2 = concurrentHashMap2.entrySet().iterator();
                    while (it2.hasNext()) {
                        arrayList.add((com.facebook.internal.gatekeeper.a) ((Map.Entry) it2.next()).getValue());
                    }
                }
            }
            if (arrayList != null) {
                map = new HashMap();
                for (com.facebook.internal.gatekeeper.a aVar : arrayList) {
                    map.put(aVar.a, Boolean.valueOf(aVar.b));
                }
            } else {
                HashMap map2 = new HashMap();
                JSONObject jSONObject = (JSONObject) concurrentHashMap.get(appId);
                if (jSONObject == null) {
                    jSONObject = new JSONObject();
                }
                Iterator<String> itKeys = jSONObject.keys();
                while (itKeys.hasNext()) {
                    String key = itKeys.next();
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    map2.put(key, Boolean.valueOf(jSONObject.optBoolean(key)));
                }
                androidx.appcompat.app.Q q2 = e;
                if (q2 == null) {
                    q2 = new androidx.appcompat.app.Q(19);
                }
                ArrayList gateKeeperList = new ArrayList(map2.size());
                for (Map.Entry entry : map2.entrySet()) {
                    gateKeeperList.add(new com.facebook.internal.gatekeeper.a((String) entry.getKey(), ((Boolean) entry.getValue()).booleanValue()));
                }
                Intrinsics.checkNotNullParameter(appId, "appId");
                Intrinsics.checkNotNullParameter(gateKeeperList, "gateKeeperList");
                ConcurrentHashMap concurrentHashMap3 = new ConcurrentHashMap();
                Iterator it3 = gateKeeperList.iterator();
                while (it3.hasNext()) {
                    com.facebook.internal.gatekeeper.a aVar2 = (com.facebook.internal.gatekeeper.a) it3.next();
                    concurrentHashMap3.put(aVar2.a, aVar2);
                }
                ((ConcurrentHashMap) q2.a).put(appId, concurrentHashMap3);
                e = q2;
                map = map2;
            }
        } else {
            map = new HashMap();
        }
        return (map.containsKey(name) && (bool = (Boolean) map.get(name)) != null) ? bool.booleanValue() : z;
    }

    public static final synchronized void c(r rVar) {
        if (rVar != null) {
            try {
                b.add(rVar);
            } catch (Throwable th) {
                throw th;
            }
        }
        String strB = com.facebook.o.b();
        Long l = d;
        if (l != null && System.currentTimeMillis() - l.longValue() < 3600000 && c.containsKey(strB)) {
            e();
            return;
        }
        Context contextA = com.facebook.o.a();
        String str = String.format("com.facebook.internal.APP_GATEKEEPERS.%s", Arrays.copyOf(new Object[]{strB}, 1));
        Intrinsics.checkNotNullExpressionValue(str, "format(format, *args)");
        JSONObject jSONObject = null;
        String string = contextA.getSharedPreferences("com.facebook.internal.preferences.APP_GATEKEEPERS", 0).getString(str, null);
        if (!J.D(string)) {
            try {
                jSONObject = new JSONObject(string);
            } catch (JSONException unused) {
                com.facebook.o oVar = com.facebook.o.a;
            }
            if (jSONObject != null) {
                d(strB, jSONObject);
            }
        }
        Executor executorC = com.facebook.o.c();
        if (a.compareAndSet(false, true)) {
            executorC.execute(new t(strB, contextA, str));
        }
    }

    public static final synchronized JSONObject d(String applicationId, JSONObject jSONObject) {
        JSONObject jSONObject2;
        try {
            Intrinsics.checkNotNullParameter(applicationId, "applicationId");
            jSONObject2 = (JSONObject) c.get(applicationId);
            if (jSONObject2 == null) {
                jSONObject2 = new JSONObject();
            }
            JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("data");
            JSONObject jSONObjectOptJSONObject = jSONArrayOptJSONArray != null ? jSONArrayOptJSONArray.optJSONObject(0) : null;
            if (jSONObjectOptJSONObject == null) {
                jSONObjectOptJSONObject = new JSONObject();
            }
            JSONArray jSONArrayOptJSONArray2 = jSONObjectOptJSONObject.optJSONArray("gatekeepers");
            if (jSONArrayOptJSONArray2 == null) {
                jSONArrayOptJSONArray2 = new JSONArray();
            }
            int length = jSONArrayOptJSONArray2.length();
            for (int i = 0; i < length; i++) {
                try {
                    JSONObject jSONObject3 = jSONArrayOptJSONArray2.getJSONObject(i);
                    jSONObject2.put(jSONObject3.getString("key"), jSONObject3.getBoolean("value"));
                } catch (JSONException unused) {
                    com.facebook.o oVar = com.facebook.o.a;
                }
            }
            c.put(applicationId, jSONObject2);
        } catch (Throwable th) {
            throw th;
        }
        return jSONObject2;
    }

    public static void e() {
        Handler handler = new Handler(Looper.getMainLooper());
        while (true) {
            ConcurrentLinkedQueue concurrentLinkedQueue = b;
            if (concurrentLinkedQueue.isEmpty()) {
                return;
            }
            r rVar = (r) concurrentLinkedQueue.poll();
            if (rVar != null) {
                handler.post(new androidx.compose.ui.text.input.C(rVar, 21));
            }
        }
    }
}
