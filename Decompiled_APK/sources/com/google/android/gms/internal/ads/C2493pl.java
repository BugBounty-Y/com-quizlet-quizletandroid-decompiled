package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.RemoteException;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.InterfaceC1603k0;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.pl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2493pl {
    public final C2536ql a;
    public final C2750vl b;
    public final C2062fl c;
    public final C2278kl d;
    public final C2018el e;
    public final BinderC2707ul f;
    public final SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc g;
    public final SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc h;
    public final String i;
    public final Context j;
    public final String k;
    public JSONObject p;
    public boolean s;
    public int t;
    public boolean u;
    public final HashMap l = new HashMap();
    public final HashMap m = new HashMap();
    public final HashMap n = new HashMap();
    public String o = "{}";
    public long q = Long.MAX_VALUE;
    public EnumC2321ll r = EnumC2321ll.a;
    public EnumC2450ol v = EnumC2450ol.a;
    public long w = 0;
    public String x = "";

    public C2493pl(C2536ql c2536ql, C2750vl c2750vl, C2062fl c2062fl, Context context, VersionInfoParcel versionInfoParcel, C2278kl c2278kl, BinderC2707ul binderC2707ul, SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc, SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc2, String str) {
        this.a = c2536ql;
        this.b = c2750vl;
        this.c = c2062fl;
        this.e = new C2018el(context);
        this.i = versionInfoParcel.a;
        this.k = str;
        this.d = c2278kl;
        this.f = binderC2707ul;
        this.g = sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc;
        this.h = sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc2;
        this.j = context;
        com.google.android.gms.ads.internal.j.C.o.g = this;
    }

    public final synchronized C2313ld a(String str) {
        C2313ld c2313ld;
        try {
            c2313ld = new C2313ld();
            HashMap map = this.m;
            if (map.containsKey(str)) {
                c2313ld.c((C2150hl) map.get(str));
            } else {
                HashMap map2 = this.n;
                if (!map2.containsKey(str)) {
                    map2.put(str, new ArrayList());
                }
                ((List) map2.get(str)).add(c2313ld);
            }
        } catch (Throwable th) {
            throw th;
        }
        return c2313ld;
    }

    public final synchronized void b(String str, C2150hl c2150hl) {
        C2601s7 c2601s7 = AbstractC2773w7.U8;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && f()) {
            if (this.t >= ((Integer) rVar.c.a(AbstractC2773w7.W8)).intValue()) {
                com.google.android.gms.ads.internal.util.client.i.h("Maximum number of ad requests stored reached. Dropping the current request.");
                return;
            }
            HashMap map = this.l;
            if (!map.containsKey(str)) {
                map.put(str, new ArrayList());
            }
            this.t++;
            ((List) map.get(str)).add(c2150hl);
            if (((Boolean) rVar.c.a(AbstractC2773w7.s9)).booleanValue()) {
                String str2 = c2150hl.c;
                this.m.put(str2, c2150hl);
                HashMap map2 = this.n;
                if (map2.containsKey(str2)) {
                    List list = (List) map2.get(str2);
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        ((C2313ld) it2.next()).c(c2150hl);
                    }
                    list.clear();
                }
            }
        }
    }

    public final void c() throws JSONException {
        String str;
        boolean z;
        C2601s7 c2601s7 = AbstractC2773w7.U8;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            if (((Boolean) rVar.c.a(AbstractC2773w7.j9)).booleanValue()) {
                com.google.android.gms.ads.internal.util.C cD = com.google.android.gms.ads.internal.j.C.h.d();
                cD.l();
                synchronized (cD.a) {
                    z = cD.y;
                }
                if (z) {
                    h();
                    return;
                }
            }
            com.google.android.gms.ads.internal.util.C cD2 = com.google.android.gms.ads.internal.j.C.h.d();
            cD2.l();
            synchronized (cD2.a) {
                str = cD2.x;
            }
            if (TextUtils.isEmpty(str)) {
                return;
            }
            try {
                if (new JSONObject(str).optBoolean("isTestMode", false)) {
                    h();
                }
            } catch (JSONException unused) {
            }
        }
    }

    public final synchronized void d(InterfaceC1603k0 interfaceC1603k0, EnumC2450ol enumC2450ol) {
        if (!f()) {
            try {
                interfaceC1603k0.T1(AbstractC1972di.x(18, null, null));
                return;
            } catch (RemoteException unused) {
                com.google.android.gms.ads.internal.util.client.i.h("Ad inspector cannot be opened because the device is not in test mode. See https://developers.google.com/admob/android/test-ads#enable_test_devices for more information.");
                return;
            }
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U8)).booleanValue()) {
            this.v = enumC2450ol;
            this.a.a(interfaceC1603k0, new C2432o9(this, 1), new C1956d9(this.f, 3), new C2432o9(this, 0));
            return;
        } else {
            try {
                interfaceC1603k0.T1(AbstractC1972di.x(1, null, null));
                return;
            } catch (RemoteException unused2) {
                com.google.android.gms.ads.internal.util.client.i.h("Ad inspector had an internal error.");
                return;
            }
        }
    }

    public final void e(boolean z) throws JSONException {
        if (!this.u && z) {
            h();
        }
        k(z, true);
    }

    public final synchronized boolean f() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.j9)).booleanValue()) {
            return this.s || com.google.android.gms.ads.internal.j.C.o.g();
        }
        return this.s;
    }

    public final synchronized JSONObject g() {
        JSONObject jSONObject;
        try {
            jSONObject = new JSONObject();
            for (Map.Entry entry : this.l.entrySet()) {
                JSONArray jSONArray = new JSONArray();
                for (C2150hl c2150hl : (List) entry.getValue()) {
                    if (c2150hl.e != EnumC2106gl.a) {
                        jSONArray.put(c2150hl.a());
                    }
                }
                if (jSONArray.length() > 0) {
                    jSONObject.put((String) entry.getKey(), jSONArray);
                }
            }
        } catch (Throwable th) {
            throw th;
        }
        return jSONObject;
    }

    public final void h() throws JSONException {
        String str;
        String str2;
        this.u = true;
        C2278kl c2278kl = this.d;
        c2278kl.getClass();
        com.google.android.gms.ads.internal.client.B0 b0 = new com.google.android.gms.ads.internal.client.B0(c2278kl, 1);
        C1931cl c1931cl = c2278kl.a;
        c1931cl.getClass();
        c1931cl.e.a.a(new Qv(27, c1931cl, b0), c1931cl.j);
        this.a.c = this;
        this.b.f = this;
        this.c.i = this;
        this.f.f = this;
        C2601s7 c2601s7 = AbstractC2773w7.x9;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (!TextUtils.isEmpty((CharSequence) rVar.c.a(c2601s7))) {
            SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(this.j);
            List listAsList = Arrays.asList(((String) rVar.c.a(c2601s7)).split(","));
            SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc = this.g;
            sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc.c = listAsList;
            defaultSharedPreferences.registerOnSharedPreferenceChangeListener(sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc);
            Iterator it2 = listAsList.iterator();
            while (it2.hasNext()) {
                sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc.onSharedPreferenceChanged(defaultSharedPreferences, (String) it2.next());
            }
        }
        C2601s7 c2601s72 = AbstractC2773w7.y9;
        if (!TextUtils.isEmpty((CharSequence) rVar.c.a(c2601s72))) {
            SharedPreferences sharedPreferences = this.j.getSharedPreferences("admob", 0);
            List listAsList2 = Arrays.asList(((String) rVar.c.a(c2601s72)).split(","));
            SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc2 = this.h;
            sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc2.c = listAsList2;
            sharedPreferences.registerOnSharedPreferenceChangeListener(sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc2);
            Iterator it3 = listAsList2.iterator();
            while (it3.hasNext()) {
                sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc2.onSharedPreferenceChanged(sharedPreferences, (String) it3.next());
            }
        }
        com.google.android.gms.ads.internal.util.C cD = com.google.android.gms.ads.internal.j.C.h.d();
        cD.l();
        synchronized (cD.a) {
            str = cD.x;
        }
        synchronized (this) {
            if (!TextUtils.isEmpty(str)) {
                try {
                    JSONObject jSONObject = new JSONObject(str);
                    k(jSONObject.optBoolean("isTestMode", false), false);
                    j((EnumC2321ll) Enum.valueOf(EnumC2321ll.class, jSONObject.optString("gesture", "NONE")), false);
                    this.o = jSONObject.optString("networkExtras", "{}");
                    this.q = jSONObject.optLong("networkExtrasExpirationSecs", Long.MAX_VALUE);
                } catch (JSONException unused) {
                }
            }
        }
        com.google.android.gms.ads.internal.util.C cD2 = com.google.android.gms.ads.internal.j.C.h.d();
        cD2.l();
        synchronized (cD2.a) {
            str2 = cD2.A;
        }
        this.x = str2;
    }

    public final void i() {
        String string;
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        com.google.android.gms.ads.internal.util.C cD = jVar.h.d();
        synchronized (this) {
            JSONObject jSONObject = new JSONObject();
            try {
                jSONObject.put("isTestMode", this.s);
                jSONObject.put("gesture", this.r);
                long j = this.q;
                jVar.k.getClass();
                if (j > System.currentTimeMillis() / 1000) {
                    jSONObject.put("networkExtras", this.o);
                    jSONObject.put("networkExtrasExpirationSecs", this.q);
                }
            } catch (JSONException unused) {
            }
            string = jSONObject.toString();
        }
        cD.getClass();
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U8)).booleanValue()) {
            cD.l();
            synchronized (cD.a) {
                try {
                    if (cD.x.equals(string)) {
                        return;
                    }
                    cD.x = string;
                    SharedPreferences.Editor editor = cD.g;
                    if (editor != null) {
                        editor.putString("inspector_info", string);
                        cD.g.apply();
                    }
                    cD.m();
                } finally {
                }
            }
        }
    }

    public final synchronized void j(EnumC2321ll enumC2321ll, boolean z) {
        try {
            if (this.r != enumC2321ll) {
                if (f()) {
                    l();
                }
                this.r = enumC2321ll;
                if (f()) {
                    m();
                }
                if (z) {
                    i();
                }
            }
        } finally {
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x002d A[Catch: all -> 0x0027, TryCatch #0 {all -> 0x0027, blocks: (B:3:0x0001, B:6:0x0006, B:8:0x000a, B:10:0x001c, B:15:0x0029, B:20:0x0038, B:16:0x002d, B:18:0x0033), top: B:27:0x0001 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void k(boolean r2, boolean r3) {
        /*
            r1 = this;
            monitor-enter(r1)
            boolean r0 = r1.s     // Catch: java.lang.Throwable -> L27
            if (r0 != r2) goto L6
            goto L3d
        L6:
            r1.s = r2     // Catch: java.lang.Throwable -> L27
            if (r2 == 0) goto L2d
            com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.j9     // Catch: java.lang.Throwable -> L27
            com.google.android.gms.ads.internal.client.r r0 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L27
            com.google.android.gms.internal.ads.u7 r0 = r0.c     // Catch: java.lang.Throwable -> L27
            java.lang.Object r2 = r0.a(r2)     // Catch: java.lang.Throwable -> L27
            java.lang.Boolean r2 = (java.lang.Boolean) r2     // Catch: java.lang.Throwable -> L27
            boolean r2 = r2.booleanValue()     // Catch: java.lang.Throwable -> L27
            if (r2 == 0) goto L29
            com.google.android.gms.ads.internal.j r2 = com.google.android.gms.ads.internal.j.C     // Catch: java.lang.Throwable -> L27
            androidx.camera.camera2.interop.c r2 = r2.o     // Catch: java.lang.Throwable -> L27
            boolean r2 = r2.g()     // Catch: java.lang.Throwable -> L27
            if (r2 != 0) goto L2d
            goto L29
        L27:
            r2 = move-exception
            goto L3f
        L29:
            r1.m()     // Catch: java.lang.Throwable -> L27
            goto L36
        L2d:
            boolean r2 = r1.f()     // Catch: java.lang.Throwable -> L27
            if (r2 != 0) goto L36
            r1.l()     // Catch: java.lang.Throwable -> L27
        L36:
            if (r3 == 0) goto L3d
            r1.i()     // Catch: java.lang.Throwable -> L27
            monitor-exit(r1)
            return
        L3d:
            monitor-exit(r1)
            return
        L3f:
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L27
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2493pl.k(boolean, boolean):void");
    }

    public final synchronized void l() {
        SensorManager sensorManager;
        Sensor sensor;
        try {
            int iOrdinal = this.r.ordinal();
            if (iOrdinal == 1) {
                C2750vl c2750vl = this.b;
                synchronized (c2750vl) {
                    try {
                        if (c2750vl.g) {
                            SensorManager sensorManager2 = c2750vl.b;
                            if (sensorManager2 != null) {
                                sensorManager2.unregisterListener(c2750vl, c2750vl.c);
                                com.google.android.gms.ads.internal.util.A.l("Stopped listening for shake gestures.");
                            }
                            c2750vl.g = false;
                        }
                    } finally {
                    }
                }
                return;
            }
            if (iOrdinal != 2) {
                return;
            }
            C2062fl c2062fl = this.c;
            synchronized (c2062fl) {
                try {
                    if (c2062fl.j && (sensorManager = c2062fl.a) != null && (sensor = c2062fl.b) != null) {
                        sensorManager.unregisterListener(c2062fl, sensor);
                        c2062fl.j = false;
                        com.google.android.gms.ads.internal.util.A.l("Stopped listening for flick gestures.");
                    }
                } finally {
                }
            }
            return;
        } catch (Throwable th) {
            throw th;
        }
        throw th;
    }

    public final synchronized void m() {
        int iOrdinal = this.r.ordinal();
        if (iOrdinal == 1) {
            this.b.b();
        } else {
            if (iOrdinal != 2) {
                return;
            }
            this.c.b();
        }
    }
}
