package com.google.android.gms.ads.nonagon.signalgeneration;

import android.text.TextUtils;
import android.util.Pair;
import androidx.appcompat.view.menu.RunnableC0069f;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.Ek;
import com.google.android.gms.internal.ads.Kk;
import com.google.android.gms.internal.ads.SharedPreferencesOnSharedPreferenceChangeListenerC2687u7;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.ConcurrentModificationException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class F {
    public final int a;
    public final long b;
    public final boolean c;
    public final boolean d;
    public final Map e;
    public final ArrayDeque f = new ArrayDeque();
    public final ArrayDeque g = new ArrayDeque();
    public final Kk h;
    public ConcurrentHashMap i;

    public F(Kk kk) {
        this.h = kk;
        C2601s7 c2601s7 = AbstractC2773w7.P6;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        this.a = ((Integer) rVar.c.a(c2601s7)).intValue();
        C2601s7 c2601s72 = AbstractC2773w7.Q6;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        this.b = ((Long) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).longValue();
        this.c = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.U6)).booleanValue();
        this.d = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.T6)).booleanValue();
        this.e = Collections.synchronizedMap(new D(this));
    }

    public final synchronized String a(String str, Ek ek) {
        E e = (E) this.e.get(str);
        ek.a.put("request_id", str);
        if (e == null) {
            ek.a.put("mhit", "false");
            return null;
        }
        ek.a.put("mhit", "true");
        return e.b;
    }

    public final synchronized void b(String str, String str2, Ek ek) {
        com.google.android.gms.ads.internal.j.C.k.getClass();
        this.e.put(str, new E(Long.valueOf(System.currentTimeMillis()), str2, new HashSet()));
        e();
        c(ek);
    }

    public final synchronized void c(Ek ek) throws Throwable {
        try {
            try {
                if (this.c) {
                    ArrayDeque arrayDeque = this.g;
                    ArrayDeque arrayDequeClone = arrayDeque.clone();
                    arrayDeque.clear();
                    ArrayDeque arrayDeque2 = this.f;
                    ArrayDeque arrayDequeClone2 = arrayDeque2.clone();
                    arrayDeque2.clear();
                    AbstractC2270kd.a.execute(new RunnableC0069f(6, this, ek, arrayDequeClone, arrayDequeClone2, false));
                }
            } catch (Throwable th) {
                th = th;
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            throw th;
        }
    }

    public final void d(Ek ek, ArrayDeque arrayDeque, String str) {
        Pair pair;
        while (!arrayDeque.isEmpty()) {
            Pair pair2 = (Pair) arrayDeque.poll();
            ConcurrentHashMap concurrentHashMap = new ConcurrentHashMap(ek.a);
            this.i = concurrentHashMap;
            concurrentHashMap.put("action", "ev");
            this.i.put("e_r", str);
            this.i.put("e_id", (String) pair2.first);
            if (this.d) {
                try {
                    JSONObject jSONObject = new JSONObject((String) pair2.second);
                    pair = new Pair(AbstractC3429b3.d(jSONObject.getJSONObject("extras").getString("query_info_type")), jSONObject.getString("request_agent"));
                } catch (JSONException unused) {
                    pair = new Pair("", "");
                }
                ConcurrentHashMap concurrentHashMap2 = this.i;
                String str2 = (String) pair.first;
                if (!TextUtils.isEmpty(str2)) {
                    concurrentHashMap2.put("e_type", str2);
                }
                ConcurrentHashMap concurrentHashMap3 = this.i;
                String str3 = (String) pair.second;
                if (!TextUtils.isEmpty(str3)) {
                    concurrentHashMap3.put("e_agent", str3);
                }
            }
            this.h.b(this.i, false);
        }
    }

    public final synchronized void e() {
        com.google.android.gms.ads.internal.j.C.k.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        try {
            Iterator it2 = this.e.entrySet().iterator();
            while (it2.hasNext()) {
                Map.Entry entry = (Map.Entry) it2.next();
                if (jCurrentTimeMillis - ((E) entry.getValue()).a.longValue() <= this.b) {
                    break;
                }
                this.g.add(new Pair((String) entry.getKey(), ((E) entry.getValue()).b));
                it2.remove();
            }
        } catch (ConcurrentModificationException e) {
            com.google.android.gms.ads.internal.j.C.h.h("QueryJsonMap.removeExpiredEntries", e);
        }
    }
}
