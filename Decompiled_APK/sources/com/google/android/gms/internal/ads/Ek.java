package com.google.android.gms.internal.ads;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public final class Ek {
    public final ConcurrentHashMap a;
    public final C2098gd b;
    public final C2023eq c;
    public final Bundle d = new Bundle();

    public Ek(Context context, Kk kk, C2098gd c2098gd, C2023eq c2023eq, String str, String str2, com.google.android.gms.ads.internal.e eVar) {
        kk.getClass();
        ConcurrentHashMap concurrentHashMap = new ConcurrentHashMap(kk.a);
        this.a = concurrentHashMap;
        this.b = c2098gd;
        this.c = c2023eq;
        concurrentHashMap.put("ad_format", str2.toUpperCase(Locale.ROOT));
        C2601s7 c2601s7 = AbstractC2773w7.A9;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        ActivityManager.MemoryInfo memoryInfo = null;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            int i = eVar.o;
            int i2 = i - 1;
            if (i == 0) {
                throw null;
            }
            concurrentHashMap.put("asv", i2 != 0 ? i2 != 1 ? "na" : "2" : "1");
        }
        C2601s7 c2601s72 = AbstractC2773w7.h2;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue()) {
            Runtime runtime = Runtime.getRuntime();
            a("rt_f", String.valueOf(runtime.freeMemory()));
            a("rt_m", String.valueOf(runtime.maxMemory()));
            a("rt_t", String.valueOf(runtime.totalMemory()));
            a("wv_c", String.valueOf(com.google.android.gms.ads.internal.j.C.h.j.get()));
            if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.p2)).booleanValue()) {
                ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
                if (activityManager != null) {
                    memoryInfo = new ActivityManager.MemoryInfo();
                    try {
                        activityManager.getMemoryInfo(memoryInfo);
                    } catch (NullPointerException unused) {
                        com.google.android.gms.ads.internal.util.client.i.h("Error retrieving the memory information.");
                    }
                }
                if (memoryInfo != null) {
                    a("mem_avl", String.valueOf(memoryInfo.availMem));
                    a("mem_tt", String.valueOf(memoryInfo.totalMem));
                    a("low_m", true != memoryInfo.lowMemory ? "0" : "1");
                }
            }
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.R6)).booleanValue()) {
            int iG = AbstractC3429b3.g(c2023eq) - 1;
            if (iG == 0) {
                concurrentHashMap.put("request_id", str);
                concurrentHashMap.put("scar", "false");
                return;
            }
            if (iG == 1) {
                concurrentHashMap.put("request_id", str);
                concurrentHashMap.put("se", "query_g");
            } else if (iG == 2) {
                concurrentHashMap.put("se", "r_adinfo");
            } else if (iG != 3) {
                concurrentHashMap.put("se", "r_both");
            } else {
                concurrentHashMap.put("se", "r_adstring");
            }
            concurrentHashMap.put("scar", "true");
            zzm zzmVar = c2023eq.d;
            a("ragent", zzmVar.p);
            a("rtype", AbstractC3429b3.d(AbstractC3429b3.e(zzmVar)));
        }
    }

    public final void a(String str, String str2) {
        if (TextUtils.isEmpty(str) || TextUtils.isEmpty(str2)) {
            return;
        }
        this.a.put(str, str2);
    }

    public final void b(Bundle bundle) {
        if (bundle == null) {
            return;
        }
        if (bundle.containsKey("cnt")) {
            a("network_coarse", Integer.toString(bundle.getInt("cnt")));
        }
        if (bundle.containsKey("gnt")) {
            a("network_fine", Integer.toString(bundle.getInt("gnt")));
        }
    }
}
