package com.snowplowanalytics.core.session;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.StrictMode;
import com.google.android.gms.internal.mlkit_vision_barcode.E6;
import com.google.firebase.crashlytics.internal.settings.d;
import com.snowplowanalytics.core.tracker.e;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public final class c {
    public static final a q = new a();
    public boolean a;
    public final String b;
    public volatile int c;
    public volatile int d;
    public d e;
    public final AtomicBoolean f;
    public final AtomicBoolean g;
    public volatile boolean h;
    public final long i;
    public final long j;
    public Runnable k;
    public Runnable l;
    public Runnable m;
    public Runnable n;
    public androidx.core.util.a o;
    public final SharedPreferences p;

    /* JADX WARN: Removed duplicated region for block: B:14:0x0074 A[Catch: all -> 0x00bf, TryCatch #1 {, blocks: (B:12:0x0070, B:15:0x0081, B:18:0x0092, B:14:0x0074), top: B:29:0x0070, outer: #0 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public c(long r4, long r6, java.util.concurrent.TimeUnit r8, android.app.Activity r9, boolean r10) {
        /*
            r3 = this;
            java.lang.String r0 = "appTracker"
            java.lang.String r1 = "timeUnit"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r1)
            java.lang.String r1 = "context"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r1)
            r3.<init>()
            r3.a = r10
            java.util.concurrent.atomic.AtomicBoolean r10 = new java.util.concurrent.atomic.AtomicBoolean
            r1 = 0
            r10.<init>(r1)
            r3.f = r10
            java.util.concurrent.atomic.AtomicBoolean r10 = new java.util.concurrent.atomic.AtomicBoolean
            r2 = 1
            r10.<init>(r2)
            r3.g = r10
            long r4 = r8.toMillis(r4)
            r3.i = r4
            long r4 = r8.toMillis(r6)
            r3.j = r4
            r3.h = r2
            boolean r4 = r3.a
            r4 = r4 ^ r2
            r10.set(r4)
            kotlin.text.Regex r4 = new kotlin.text.Regex
            java.lang.String r5 = "[^a-zA-Z0-9_]+"
            r4.<init>(r5)
            java.lang.String r5 = "-"
            java.lang.String r4 = r4.replace(r0, r5)
            java.lang.String r5 = "snowplow_session_vars_"
            java.lang.String r4 = androidx.camera.camera2.internal.AbstractC0147y.d(r5, r4)
            android.os.StrictMode$ThreadPolicy r5 = android.os.StrictMode.allowThreadDiskReads()
            java.util.HashMap r6 = b(r9, r4)     // Catch: java.lang.Throwable -> L61
            if (r6 != 0) goto L63
            java.lang.String r6 = "c"
            java.lang.String r7 = "TAG"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r7)     // Catch: java.lang.Throwable -> L61
            java.lang.String r7 = "No previous session info available"
            java.lang.Object[] r8 = new java.lang.Object[r1]     // Catch: java.lang.Throwable -> L61
            com.snowplowanalytics.core.tracker.e.d(r6, r7, r8)     // Catch: java.lang.Throwable -> L61
            goto L69
        L61:
            r4 = move-exception
            goto Lc2
        L63:
            com.google.firebase.crashlytics.internal.settings.d r6 = com.google.android.gms.internal.mlkit_vision_barcode.G6.a(r6)     // Catch: java.lang.Throwable -> L61
            r3.e = r6     // Catch: java.lang.Throwable -> L61
        L69:
            com.snowplowanalytics.core.session.a r6 = com.snowplowanalytics.core.session.c.q     // Catch: java.lang.Throwable -> L61
            com.google.firebase.crashlytics.internal.settings.d r7 = r3.e     // Catch: java.lang.Throwable -> L61
            monitor-enter(r6)     // Catch: java.lang.Throwable -> L61
            if (r7 == 0) goto L74
            java.lang.String r7 = r7.f     // Catch: java.lang.Throwable -> Lbf
            if (r7 != 0) goto L81
        L74:
            java.util.UUID r7 = java.util.UUID.randomUUID()     // Catch: java.lang.Throwable -> Lbf
            java.lang.String r7 = r7.toString()     // Catch: java.lang.Throwable -> Lbf
            java.lang.String r8 = "randomUUID().toString()"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r8)     // Catch: java.lang.Throwable -> Lbf
        L81:
            java.lang.String r8 = "snowplow_general_vars"
            android.content.SharedPreferences r8 = r9.getSharedPreferences(r8, r1)     // Catch: java.lang.Throwable -> Lbf
            java.lang.String r10 = "SPInstallationUserId"
            r0 = 0
            java.lang.String r10 = r8.getString(r10, r0)     // Catch: java.lang.Throwable -> Lbf
            if (r10 == 0) goto L92
            r7 = r10
            goto L9f
        L92:
            android.content.SharedPreferences$Editor r8 = r8.edit()     // Catch: java.lang.Throwable -> Lbf
            java.lang.String r10 = "SPInstallationUserId"
            android.content.SharedPreferences$Editor r8 = r8.putString(r10, r7)     // Catch: java.lang.Throwable -> Lbf
            r8.commit()     // Catch: java.lang.Throwable -> Lbf
        L9f:
            monitor-exit(r6)     // Catch: java.lang.Throwable -> L61
            r3.b = r7     // Catch: java.lang.Throwable -> L61
            android.content.SharedPreferences r4 = r9.getSharedPreferences(r4, r1)     // Catch: java.lang.Throwable -> L61
            java.lang.String r6 = "context.getSharedPrefere…me, Context.MODE_PRIVATE)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r6)     // Catch: java.lang.Throwable -> L61
            r3.p = r4     // Catch: java.lang.Throwable -> L61
            android.os.StrictMode.setThreadPolicy(r5)
            java.lang.String r4 = "c"
            java.lang.String r5 = "TAG"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r5)
            java.lang.String r5 = "Tracker Session Object created."
            java.lang.Object[] r6 = new java.lang.Object[r1]
            com.snowplowanalytics.core.tracker.e.e(r4, r5, r6)
            return
        Lbf:
            r4 = move-exception
            monitor-exit(r6)     // Catch: java.lang.Throwable -> Lbf
            throw r4     // Catch: java.lang.Throwable -> L61
        Lc2:
            android.os.StrictMode.setThreadPolicy(r5)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.snowplowanalytics.core.session.c.<init>(long, long, java.util.concurrent.TimeUnit, android.app.Activity, boolean):void");
    }

    public static void a(Runnable runnable) {
        if (runnable == null) {
            return;
        }
        try {
            runnable.run();
        } catch (Exception unused) {
            Intrinsics.checkNotNullExpressionValue("c", "TAG");
            e.b("c", "Session event callback failed", new Object[0]);
        }
    }

    public static HashMap b(Activity activity, String str) {
        StrictMode.ThreadPolicy threadPolicyAllowThreadDiskReads = StrictMode.allowThreadDiskReads();
        try {
            try {
                SharedPreferences sharedPreferences = activity.getSharedPreferences(str, 0);
                if (!sharedPreferences.contains("session_state")) {
                    StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskReads);
                    return null;
                }
                HashMap map = new HashMap();
                String string = sharedPreferences.getString("session_state", null);
                JSONObject jSONObject = string != null ? new JSONObject(string) : null;
                Iterator<String> itKeys = jSONObject != null ? jSONObject.keys() : null;
                while (itKeys != null) {
                    if (!itKeys.hasNext()) {
                        break;
                    }
                    String next = itKeys.next();
                    map.put(next, jSONObject.get(next));
                }
                StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskReads);
                return map;
            } catch (JSONException e) {
                e.printStackTrace();
                StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskReads);
                return null;
            }
        } catch (Throwable th) {
            StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskReads);
            throw th;
        }
    }

    public final void c() {
        d dVar = this.e;
        if (dVar != null) {
            LinkedHashMap linkedHashMapM = V.m(dVar.a());
            Long l = (Long) dVar.i;
            if (l != null) {
                linkedHashMapM.put("lastUpdate", Long.valueOf(l.longValue()));
            }
            String string = new JSONObject(linkedHashMapM).toString();
            Intrinsics.checkNotNullExpressionValue(string, "jsonObject.toString()");
            SharedPreferences.Editor editorEdit = this.p.edit();
            editorEdit.putString("session_state", string);
            editorEdit.apply();
        }
    }

    public final void d(boolean z) {
        Intrinsics.checkNotNullExpressionValue("c", "TAG");
        e.a("c", "Session is suspended: %s", Boolean.valueOf(z));
        this.h = !z;
    }

    public final synchronized void e(long j, String str) {
        try {
            this.g.set(false);
            d dVar = this.e;
            if (dVar == null) {
                String strC = E6.c(j);
                String string = UUID.randomUUID().toString();
                Intrinsics.checkNotNullExpressionValue(string, "randomUUID().toString()");
                this.e = new d(str, strC, string, (String) null, 1, this.b, "LOCAL_STORAGE", (Integer) null, (Long) null);
            } else {
                dVar.b(j, str);
            }
        } catch (Throwable th) {
            throw th;
        }
    }
}
