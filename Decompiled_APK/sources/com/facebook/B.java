package com.facebook;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import androidx.compose.foundation.layout.T;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.C1548c;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class B {
    public static final B a = new B();
    public static final AtomicBoolean b = new AtomicBoolean(false);
    public static final AtomicBoolean c = new AtomicBoolean(false);
    public static final T d = new T(true, "com.facebook.sdk.AutoInitEnabled");
    public static final T e = new T(true, "com.facebook.sdk.AutoLogAppEventsEnabled");
    public static final T f = new T(true, "com.facebook.sdk.AdvertiserIDCollectionEnabled");
    public static final T g = new T(false, "auto_event_setup_enabled");
    public static final T h = new T(true, "com.facebook.sdk.MonitorEnabled");
    public static SharedPreferences i;

    public static final boolean b() {
        if (com.facebook.internal.instrument.crashshield.a.b(B.class)) {
            return false;
        }
        try {
            a.e();
            return f.a();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(B.class, th);
            return false;
        }
    }

    public static final boolean c() {
        if (com.facebook.internal.instrument.crashshield.a.b(B.class)) {
            return false;
        }
        try {
            B b2 = a;
            b2.e();
            return b2.a();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(B.class, th);
            return false;
        }
    }

    public static final Boolean j() {
        SharedPreferences sharedPreferences;
        String str = "";
        if (com.facebook.internal.instrument.crashshield.a.b(B.class)) {
            return null;
        }
        try {
            a.l();
            try {
                sharedPreferences = i;
            } catch (JSONException unused) {
                o oVar = o.a;
            }
            if (sharedPreferences == null) {
                Intrinsics.m("userSettingPref");
                throw null;
            }
            String string = sharedPreferences.getString((String) e.c, "");
            if (string != null) {
                str = string;
            }
            if (str.length() > 0) {
                return Boolean.valueOf(new JSONObject(str).getBoolean("value"));
            }
            return null;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(B.class, th);
            return null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x003c A[PHI: r2
  0x003c: PHI (r2v8 java.lang.Boolean) = (r2v6 java.lang.Boolean), (r2v7 java.lang.Boolean) binds: [B:21:0x003a, B:24:0x0042] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean a() {
        /*
            r4 = this;
            boolean r0 = com.facebook.internal.instrument.crashshield.a.b(r4)
            r1 = 0
            if (r0 == 0) goto L8
            return r1
        L8:
            java.util.HashMap r0 = com.facebook.internal.y.c()     // Catch: java.lang.Throwable -> L2c
            if (r0 == 0) goto L59
            boolean r2 = r0.isEmpty()     // Catch: java.lang.Throwable -> L2c
            if (r2 == 0) goto L15
            goto L59
        L15:
            java.lang.String r2 = "auto_log_app_events_enabled"
            java.lang.Object r2 = r0.get(r2)     // Catch: java.lang.Throwable -> L2c
            java.lang.Boolean r2 = (java.lang.Boolean) r2     // Catch: java.lang.Throwable -> L2c
            java.lang.String r3 = "auto_log_app_events_default"
            java.lang.Object r0 = r0.get(r3)     // Catch: java.lang.Throwable -> L2c
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.Throwable -> L2c
            if (r2 == 0) goto L2e
            boolean r0 = r2.booleanValue()     // Catch: java.lang.Throwable -> L2c
            return r0
        L2c:
            r0 = move-exception
            goto L60
        L2e:
            boolean r2 = com.facebook.internal.instrument.crashshield.a.b(r4)     // Catch: java.lang.Throwable -> L2c
            r3 = 0
            if (r2 == 0) goto L36
            goto L49
        L36:
            java.lang.Boolean r2 = j()     // Catch: java.lang.Throwable -> L45
            if (r2 == 0) goto L3e
        L3c:
            r3 = r2
            goto L49
        L3e:
            java.lang.Boolean r2 = r4.f()     // Catch: java.lang.Throwable -> L45
            if (r2 == 0) goto L49
            goto L3c
        L45:
            r2 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r4, r2)     // Catch: java.lang.Throwable -> L2c
        L49:
            if (r3 == 0) goto L50
            boolean r0 = r3.booleanValue()     // Catch: java.lang.Throwable -> L2c
            return r0
        L50:
            if (r0 == 0) goto L57
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> L2c
            return r0
        L57:
            r0 = 1
            return r0
        L59:
            androidx.compose.foundation.layout.T r0 = com.facebook.B.e     // Catch: java.lang.Throwable -> L2c
            boolean r0 = r0.a()     // Catch: java.lang.Throwable -> L2c
            return r0
        L60:
            com.facebook.internal.instrument.crashshield.a.a(r4, r0)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.B.a():boolean");
    }

    public final void d() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            T t = g;
            k(t);
            final long jCurrentTimeMillis = System.currentTimeMillis();
            if (((Boolean) t.d) == null || jCurrentTimeMillis - t.b >= 604800000) {
                t.d = null;
                t.b = 0L;
                if (c.compareAndSet(false, true)) {
                    o.c().execute(new Runnable() { // from class: com.facebook.A
                        @Override // java.lang.Runnable
                        public final void run() {
                            com.facebook.internal.v vVarK;
                            long j = jCurrentTimeMillis;
                            if (com.facebook.internal.instrument.crashshield.a.b(B.class)) {
                                return;
                            }
                            try {
                                if (B.f.a() && (vVarK = com.facebook.internal.y.k(o.b(), false)) != null && vVarK.g) {
                                    C1548c c1548cB = AbstractC1554i.b(o.a());
                                    String strA = (c1548cB == null || c1548cB.a() == null) ? null : c1548cB.a();
                                    if (strA != null) {
                                        Bundle bundle = new Bundle();
                                        bundle.putString("advertiser_id", strA);
                                        bundle.putString("fields", "auto_event_setup_enabled");
                                        String str = t.j;
                                        t tVarQ = assistantMode.utils.studiableMetadata.b.Q(null, "app", null);
                                        Intrinsics.checkNotNullParameter(bundle, "<set-?>");
                                        tVarQ.d = bundle;
                                        JSONObject jSONObject = tVarQ.c().b;
                                        if (jSONObject != null) {
                                            T t2 = B.g;
                                            t2.d = Boolean.valueOf(jSONObject.optBoolean("auto_event_setup_enabled", false));
                                            t2.b = j;
                                            B.a.m(t2);
                                        }
                                    }
                                }
                                B.c.set(false);
                            } catch (Throwable th) {
                                com.facebook.internal.instrument.crashshield.a.a(B.class, th);
                            }
                        }
                    });
                }
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void e() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            if (o.o.get()) {
                if (b.compareAndSet(false, true)) {
                    SharedPreferences sharedPreferences = o.a().getSharedPreferences("com.facebook.sdk.USER_SETTINGS", 0);
                    Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getApplicationContext()\n…GS, Context.MODE_PRIVATE)");
                    i = sharedPreferences;
                    T[] tArr = {e, f, d};
                    if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                        for (int i2 = 0; i2 < 3; i2++) {
                            try {
                                T t = tArr[i2];
                                if (t == g) {
                                    d();
                                } else if (((Boolean) t.d) == null) {
                                    k(t);
                                    if (((Boolean) t.d) == null) {
                                        g(t);
                                    }
                                } else {
                                    m(t);
                                }
                            } catch (Throwable th) {
                                com.facebook.internal.instrument.crashshield.a.a(this, th);
                            }
                        }
                    }
                    d();
                    i();
                    h();
                }
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
        }
    }

    public final Boolean f() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            l();
            try {
                Context contextA = o.a();
                ApplicationInfo applicationInfo = contextA.getPackageManager().getApplicationInfo(contextA.getPackageName(), 128);
                Intrinsics.checkNotNullExpressionValue(applicationInfo, "ctx.packageManager.getAp…ageManager.GET_META_DATA)");
                Bundle bundle = applicationInfo.metaData;
                if (bundle != null) {
                    T t = e;
                    if (bundle.containsKey((String) t.c)) {
                        return Boolean.valueOf(applicationInfo.metaData.getBoolean((String) t.c));
                    }
                }
            } catch (PackageManager.NameNotFoundException unused) {
                o oVar = o.a;
            }
            return null;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final void g(T t) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            l();
            try {
                Context contextA = o.a();
                ApplicationInfo applicationInfo = contextA.getPackageManager().getApplicationInfo(contextA.getPackageName(), 128);
                Intrinsics.checkNotNullExpressionValue(applicationInfo, "ctx.packageManager.getAp…ageManager.GET_META_DATA)");
                Bundle bundle = applicationInfo.metaData;
                if (bundle == null || !bundle.containsKey((String) t.c)) {
                    return;
                }
                t.d = Boolean.valueOf(applicationInfo.metaData.getBoolean((String) t.c, t.a));
            } catch (PackageManager.NameNotFoundException unused) {
                o oVar = o.a;
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x00dd  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00de A[Catch: all -> 0x00a8, TryCatch #1 {all -> 0x00a8, blocks: (B:5:0x000d, B:8:0x0017, B:11:0x0021, B:15:0x004e, B:17:0x0054, B:19:0x0058, B:20:0x0063, B:22:0x007a, B:25:0x008f, B:34:0x00b4, B:39:0x00e6, B:37:0x00de, B:40:0x00ee, B:41:0x00f1, B:43:0x00f3, B:44:0x00f6), top: B:49:0x000d }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void h() {
        /*
            Method dump skipped, instructions count: 258
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.B.h():void");
    }

    public final void i() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Context contextA = o.a();
            ApplicationInfo applicationInfo = contextA.getPackageManager().getApplicationInfo(contextA.getPackageName(), 128);
            Intrinsics.checkNotNullExpressionValue(applicationInfo, "ctx.packageManager.getAp…ageManager.GET_META_DATA)");
            Bundle bundle = applicationInfo.metaData;
            if (bundle != null) {
                if (!bundle.containsKey("com.facebook.sdk.AdvertiserIDCollectionEnabled")) {
                    Log.w("com.facebook.B", "You haven't set a value for AdvertiserIDCollectionEnabled. Set the flag to TRUE if you want to collect Advertiser ID for better advertising and analytics results. To request user consent before collecting data, set the flag value to FALSE, then change to TRUE once user consent is received. Learn more: https://developers.facebook.com/docs/app-events/getting-started-app-events-android#disable-auto-events.");
                }
                if (b()) {
                    return;
                }
                Log.w("com.facebook.B", "The value for AdvertiserIDCollectionEnabled is currently set to FALSE so you're sending app events without collecting Advertiser ID. This can affect the quality of your advertising and analytics results.");
            }
        } catch (PackageManager.NameNotFoundException unused) {
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void k(T t) {
        String str = "";
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            l();
            try {
                SharedPreferences sharedPreferences = i;
                if (sharedPreferences == null) {
                    Intrinsics.m("userSettingPref");
                    throw null;
                }
                String string = sharedPreferences.getString((String) t.c, "");
                if (string != null) {
                    str = string;
                }
                if (str.length() > 0) {
                    JSONObject jSONObject = new JSONObject(str);
                    t.d = Boolean.valueOf(jSONObject.getBoolean("value"));
                    t.b = jSONObject.getLong("last_timestamp");
                }
            } catch (JSONException unused) {
                o oVar = o.a;
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void l() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            if (b.get()) {
            } else {
                throw new FacebookSdkNotInitializedException("The UserSettingManager has not been initialized successfully");
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void m(T t) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            l();
            try {
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("value", (Boolean) t.d);
                jSONObject.put("last_timestamp", t.b);
                SharedPreferences sharedPreferences = i;
                if (sharedPreferences == null) {
                    Intrinsics.m("userSettingPref");
                    throw null;
                }
                sharedPreferences.edit().putString((String) t.c, jSONObject.toString()).apply();
                h();
            } catch (Exception unused) {
                o oVar = o.a;
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
