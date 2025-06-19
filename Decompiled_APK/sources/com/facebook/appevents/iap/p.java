package com.facebook.appevents.iap;

import android.content.SharedPreferences;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class p {
    public static final p a = new p();

    /* JADX WARN: Removed duplicated region for block: B:13:0x0018 A[Catch: all -> 0x01a0, TRY_LEAVE, TryCatch #0 {, blocks: (B:4:0x0003, B:13:0x0018, B:11:0x0012, B:8:0x000e), top: B:91:0x0003, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x015a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.facebook.appevents.iap.l c(android.content.Context r20) {
        /*
            Method dump skipped, instructions count: 418
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.iap.p.c(android.content.Context):com.facebook.appevents.iap.l");
    }

    public static r d() {
        Class clsE = u.e("com.android.billingclient.api.SkuDetailsParams");
        Class clsE2 = u.e("com.android.billingclient.api.SkuDetailsParams$Builder");
        if (clsE == null || clsE2 == null) {
            return null;
        }
        Method methodG = u.g(clsE, "newBuilder", new Class[0]);
        Method methodG2 = u.g(clsE2, "setType", String.class);
        Method methodG3 = u.g(clsE2, "setSkusList", List.class);
        Method methodG4 = u.g(clsE2, "build", new Class[0]);
        if (methodG == null || methodG2 == null || methodG3 == null || methodG4 == null) {
            return null;
        }
        r rVar = new r(clsE, clsE2, methodG, methodG2, methodG3, methodG4);
        if (!com.facebook.internal.instrument.crashshield.a.b(r.class)) {
            try {
                r.h = rVar;
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(r.class, th);
            }
        }
        if (com.facebook.internal.instrument.crashshield.a.b(r.class)) {
            return null;
        }
        try {
            return r.h;
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(r.class, th2);
            return null;
        }
    }

    public static final void e() {
        if (com.facebook.internal.instrument.crashshield.a.b(p.class)) {
            return;
        }
        try {
            SharedPreferences sharedPreferences = com.facebook.o.a().getSharedPreferences("com.facebook.internal.SKU_DETAILS", 0);
            SharedPreferences sharedPreferences2 = com.facebook.o.a().getSharedPreferences("com.facebook.internal.PURCHASE", 0);
            sharedPreferences.edit().clear().apply();
            sharedPreferences2.edit().clear().apply();
            com.facebook.o.a().getSharedPreferences("com.facebook.internal.iap.PRODUCT_DETAILS", 0).edit().clear().apply();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(p.class, th);
        }
    }

    public static final void f(ConcurrentHashMap purchaseDetailsMap, ConcurrentHashMap skuDetailsMap, boolean z, String packageName, s billingClientVersion, boolean z2) {
        if (com.facebook.internal.instrument.crashshield.a.b(p.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(purchaseDetailsMap, "purchaseDetailsMap");
            Intrinsics.checkNotNullParameter(skuDetailsMap, "skuDetailsMap");
            Intrinsics.checkNotNullParameter(packageName, "packageName");
            Intrinsics.checkNotNullParameter(billingClientVersion, "billingClientVersion");
            p pVar = a;
            LinkedHashMap linkedHashMapB = pVar.b(pVar.a(purchaseDetailsMap, z), skuDetailsMap, packageName);
            if (com.facebook.internal.instrument.crashshield.a.b(pVar)) {
                return;
            }
            try {
                for (Map.Entry entry : linkedHashMapB.entrySet()) {
                    com.facebook.appevents.internal.j.d((String) entry.getKey(), (String) entry.getValue(), z, billingClientVersion, z2);
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(pVar, th);
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(p.class, th2);
        }
    }

    public static ConcurrentHashMap g() {
        if (com.facebook.internal.instrument.crashshield.a.b(l.class)) {
            return null;
        }
        try {
            return l.o;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(l.class, th);
            return null;
        }
    }

    public static ConcurrentHashMap h() {
        if (com.facebook.internal.instrument.crashshield.a.b(l.class)) {
            return null;
        }
        try {
            return l.q;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(l.class, th);
            return null;
        }
    }

    public static ConcurrentHashMap i() {
        if (com.facebook.internal.instrument.crashshield.a.b(l.class)) {
            return null;
        }
        try {
            return l.p;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(l.class, th);
            return null;
        }
    }

    public static final void j() {
        if (com.facebook.internal.instrument.crashshield.a.b(p.class)) {
            return;
        }
        try {
            SharedPreferences sharedPreferences = com.facebook.o.a().getSharedPreferences("com.facebook.internal.iap.IAP_CACHE_GPBLV2V7", 0);
            long jMax = Math.max(Math.max(sharedPreferences.getLong("TIME_OF_LAST_LOGGED_PURCHASE", 0L), sharedPreferences.getLong("TIME_OF_LAST_LOGGED_SUBSCRIPTION", 0L)), 1736528400000L);
            CopyOnWriteArraySet copyOnWriteArraySet = new CopyOnWriteArraySet();
            SharedPreferences sharedPreferences2 = com.facebook.o.a().getSharedPreferences("com.facebook.internal.iap.PRODUCT_DETAILS", 0);
            if (sharedPreferences2.contains("PURCHASE_DETAILS_SET")) {
                Collection stringSet = sharedPreferences2.getStringSet("PURCHASE_DETAILS_SET", new HashSet());
                copyOnWriteArraySet.addAll(stringSet == null ? new HashSet() : stringSet);
                Iterator it2 = copyOnWriteArraySet.iterator();
                while (it2.hasNext()) {
                    try {
                        long j = Long.parseLong((String) StringsKt__StringsKt.split$default((String) it2.next(), new String[]{";"}, false, 2, 2, null).get(1)) * 1000;
                        if (Math.abs(String.valueOf(j).length() - 13) < Math.log10(1000.0d)) {
                            jMax = Math.max(jMax, j);
                        }
                    } catch (Exception unused) {
                    }
                }
            }
            sharedPreferences.edit().putLong("TIME_OF_LAST_LOGGED_SUBSCRIPTION", jMax).apply();
            sharedPreferences.edit().putLong("TIME_OF_LAST_LOGGED_PURCHASE", jMax).apply();
            e();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(p.class, th);
        }
    }

    public static final void k() {
        if (com.facebook.internal.instrument.crashshield.a.b(p.class)) {
            return;
        }
        try {
            try {
                com.facebook.o.a().getSharedPreferences("com.facebook.internal.iap.IAP_CACHE_GPBLV2V7", 0).edit().putBoolean("APP_HAS_BEEN_LAUNCHED_KEY", true).apply();
            } catch (Exception unused) {
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(p.class, th);
        }
    }

    public static final void l() {
        if (com.facebook.internal.instrument.crashshield.a.b(p.class)) {
            return;
        }
        try {
            k();
            try {
                SharedPreferences sharedPreferences = com.facebook.o.a().getSharedPreferences("com.facebook.internal.iap.IAP_CACHE_GPBLV2V7", 0);
                long jCurrentTimeMillis = System.currentTimeMillis();
                sharedPreferences.edit().putLong("TIME_OF_LAST_LOGGED_SUBSCRIPTION", jCurrentTimeMillis).apply();
                sharedPreferences.edit().putLong("TIME_OF_LAST_LOGGED_PURCHASE", jCurrentTimeMillis).apply();
            } catch (Exception unused) {
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(p.class, th);
        }
    }

    public HashMap a(ConcurrentHashMap purchaseDetailsMap, boolean z) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(purchaseDetailsMap, "purchaseDetailsMap");
            SharedPreferences sharedPreferences = com.facebook.o.a().getSharedPreferences("com.facebook.internal.iap.IAP_CACHE_GPBLV2V7", 0);
            long j = z ? sharedPreferences.getLong("TIME_OF_LAST_LOGGED_SUBSCRIPTION", 1736528400000L) : sharedPreferences.getLong("TIME_OF_LAST_LOGGED_PURCHASE", 1736528400000L);
            long jMax = 0;
            for (Map.Entry entry : V.l(purchaseDetailsMap).entrySet()) {
                String str = (String) entry.getKey();
                JSONObject jSONObject = (JSONObject) entry.getValue();
                try {
                    if (jSONObject.has("purchaseToken") && jSONObject.has("purchaseTime")) {
                        long j2 = jSONObject.getLong("purchaseTime");
                        if (j2 <= j) {
                            purchaseDetailsMap.remove(str);
                        }
                        jMax = Math.max(jMax, j2);
                    }
                } catch (Exception unused) {
                }
            }
            if (jMax >= j) {
                if (z) {
                    sharedPreferences.edit().putLong("TIME_OF_LAST_LOGGED_SUBSCRIPTION", jMax).apply();
                } else {
                    sharedPreferences.edit().putLong("TIME_OF_LAST_LOGGED_PURCHASE", jMax).apply();
                }
            }
            return new HashMap(purchaseDetailsMap);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public LinkedHashMap b(HashMap purchaseDetailsMap, ConcurrentHashMap skuDetailsMap, String packageName) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(purchaseDetailsMap, "purchaseDetailsMap");
            Intrinsics.checkNotNullParameter(skuDetailsMap, "skuDetailsMap");
            Intrinsics.checkNotNullParameter(packageName, "packageName");
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            for (Map.Entry entry : purchaseDetailsMap.entrySet()) {
                String str = (String) entry.getKey();
                JSONObject jSONObject = (JSONObject) entry.getValue();
                JSONObject jSONObject2 = (JSONObject) skuDetailsMap.get(str);
                try {
                    jSONObject.put("packageName", packageName);
                    if (jSONObject2 != null) {
                        String string = jSONObject.toString();
                        Intrinsics.checkNotNullExpressionValue(string, "purchaseDetail.toString()");
                        String string2 = jSONObject2.toString();
                        Intrinsics.checkNotNullExpressionValue(string2, "skuDetail.toString()");
                        linkedHashMap.put(string, string2);
                    }
                } catch (Exception unused) {
                }
            }
            return linkedHashMap;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }
}
