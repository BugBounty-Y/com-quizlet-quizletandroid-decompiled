package com.facebook.appevents.iap;

import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class d {
    public static final AtomicBoolean a = new AtomicBoolean(false);
    public static Boolean b;
    public static Boolean c;
    public static b d;
    public static c e;
    public static Intent f;
    public static Object g;
    public static s h;

    public static final void a(Context context, ArrayList arrayList, boolean z) {
        if (arrayList.isEmpty()) {
            return;
        }
        HashMap map = new HashMap();
        ArrayList skuList = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            String purchase = (String) it2.next();
            try {
                String sku = new JSONObject(purchase).getString("productId");
                Intrinsics.checkNotNullExpressionValue(sku, "sku");
                Intrinsics.checkNotNullExpressionValue(purchase, "purchase");
                map.put(sku, purchase);
                skuList.add(sku);
            } catch (JSONException e2) {
                Log.e("com.facebook.appevents.iap.d", "Error parsing in-app purchase data.", e2);
            }
        }
        Object obj = g;
        o oVar = o.a;
        LinkedHashMap linkedHashMap = null;
        if (!com.facebook.internal.instrument.crashshield.a.b(o.class)) {
            try {
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(skuList, "skuList");
                o oVar2 = o.a;
                LinkedHashMap linkedHashMapJ = oVar2.j(skuList);
                ArrayList arrayList2 = new ArrayList();
                Iterator it3 = skuList.iterator();
                while (it3.hasNext()) {
                    String str = (String) it3.next();
                    if (!linkedHashMapJ.containsKey(str)) {
                        arrayList2.add(str);
                    }
                }
                linkedHashMapJ.putAll(oVar2.g(context, arrayList2, obj, z));
                linkedHashMap = linkedHashMapJ;
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(o.class, th);
            }
        }
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            String str2 = (String) entry.getKey();
            String str3 = (String) entry.getValue();
            String str4 = (String) map.get(str2);
            if (str4 != null) {
                com.facebook.appevents.internal.j.d(str4, str3, z, h, false);
            }
        }
    }

    public static final void b(s billingClientVersion) {
        Intrinsics.checkNotNullParameter(billingClientVersion, "billingClientVersion");
        if (b == null) {
            Boolean boolValueOf = Boolean.valueOf(u.e("com.android.vending.billing.IInAppBillingService$Stub") != null);
            b = boolValueOf;
            if (!boolValueOf.equals(Boolean.FALSE)) {
                c = Boolean.valueOf(u.e("com.android.billingclient.api.ProxyBillingActivity") != null);
                o oVar = o.a;
                if (!com.facebook.internal.instrument.crashshield.a.b(o.class)) {
                    try {
                        long jCurrentTimeMillis = System.currentTimeMillis() / 1000;
                        SharedPreferences sharedPreferences = o.e;
                        long j = sharedPreferences.getLong("LAST_CLEARED_TIME", 0L);
                        if (j == 0) {
                            sharedPreferences.edit().putLong("LAST_CLEARED_TIME", jCurrentTimeMillis).apply();
                        } else if (jCurrentTimeMillis - j > 604800) {
                            sharedPreferences.edit().clear().putLong("LAST_CLEARED_TIME", jCurrentTimeMillis).apply();
                        }
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(o.class, th);
                    }
                }
                Intent intent = new Intent("com.android.vending.billing.InAppBillingService.BIND").setPackage("com.android.vending");
                Intrinsics.checkNotNullExpressionValue(intent, "Intent(\"com.android.vend…ge(\"com.android.vending\")");
                f = intent;
                d = new b();
                e = new c();
            }
        }
        if (!Intrinsics.b(b, Boolean.FALSE) && com.facebook.appevents.internal.j.c()) {
            h = billingClientVersion;
            if (a.compareAndSet(false, true)) {
                Context contextA = com.facebook.o.a();
                if (contextA instanceof Application) {
                    Application application = (Application) contextA;
                    c cVar = e;
                    if (cVar == null) {
                        Intrinsics.m("callbacks");
                        throw null;
                    }
                    application.registerActivityLifecycleCallbacks(cVar);
                    Intent intent2 = f;
                    if (intent2 == null) {
                        Intrinsics.m("intent");
                        throw null;
                    }
                    b bVar = d;
                    if (bVar != null) {
                        contextA.bindService(intent2, bVar, 1);
                    } else {
                        Intrinsics.m("serviceConnection");
                        throw null;
                    }
                }
            }
        }
    }
}
