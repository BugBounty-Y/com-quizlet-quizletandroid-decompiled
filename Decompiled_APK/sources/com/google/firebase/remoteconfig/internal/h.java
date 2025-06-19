package com.google.firebase.remoteconfig.internal;

import android.content.Context;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.common.api.internal.w;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigClientException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Random;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class h {
    public static final int[] r = {2, 4, 8, 16, 32, 64, 128, 256};
    public static final Pattern s = Pattern.compile("^[^:]+:([0-9]+):(android|ios|web):([0-9a-f]+)");
    public final LinkedHashSet a;
    public int c;
    public HttpURLConnection f;
    public final ScheduledExecutorService g;
    public final e h;
    public final com.google.firebase.h i;
    public final com.google.firebase.installations.d j;
    public final b k;
    public final Context l;
    public final String m;
    public final j p;
    public boolean b = false;
    public final Random n = new Random();
    public final com.google.android.gms.common.util.b o = com.google.android.gms.common.util.b.a;
    public boolean d = false;
    public boolean e = false;
    public final Object q = new Object();

    public h(com.google.firebase.h hVar, com.google.firebase.installations.d dVar, e eVar, b bVar, Context context, String str, LinkedHashSet linkedHashSet, j jVar, ScheduledExecutorService scheduledExecutorService) {
        this.a = linkedHashSet;
        this.g = scheduledExecutorService;
        this.c = Math.max(8 - jVar.c().a, 1);
        this.i = hVar;
        this.h = eVar;
        this.j = dVar;
        this.k = bVar;
        this.l = context;
        this.m = str;
        this.p = jVar;
    }

    public static boolean d(int i) {
        return i == 408 || i == 429 || i == 502 || i == 503 || i == 504;
    }

    public static String f(InputStream inputStream) {
        StringBuilder sb = new StringBuilder();
        try {
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
            while (true) {
                String line = bufferedReader.readLine();
                if (line == null) {
                    break;
                }
                sb.append(line);
            }
        } catch (IOException unused) {
            if (sb.length() == 0) {
                return "Unable to connect to the server, access is forbidden. HTTP status code: 403";
            }
        }
        return sb.toString();
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized boolean a() {
        /*
            r1 = this;
            monitor-enter(r1)
            java.util.LinkedHashSet r0 = r1.a     // Catch: java.lang.Throwable -> L17
            boolean r0 = r0.isEmpty()     // Catch: java.lang.Throwable -> L17
            if (r0 != 0) goto L19
            boolean r0 = r1.b     // Catch: java.lang.Throwable -> L17
            if (r0 != 0) goto L19
            boolean r0 = r1.d     // Catch: java.lang.Throwable -> L17
            if (r0 != 0) goto L19
            boolean r0 = r1.e     // Catch: java.lang.Throwable -> L17
            if (r0 != 0) goto L19
            r0 = 1
            goto L1a
        L17:
            r0 = move-exception
            goto L1c
        L19:
            r0 = 0
        L1a:
            monitor-exit(r1)
            return r0
        L1c:
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L17
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.remoteconfig.internal.h.a():boolean");
    }

    public final void b(InputStream inputStream, InputStream inputStream2) {
        HttpURLConnection httpURLConnection = this.f;
        if (httpURLConnection != null && !this.e) {
            httpURLConnection.disconnect();
        }
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (IOException unused) {
            }
        }
        if (inputStream2 != null) {
            try {
                inputStream2.close();
            } catch (IOException unused2) {
            }
        }
    }

    public final String c(String str) {
        com.google.firebase.h hVar = this.i;
        hVar.a();
        Matcher matcher = s.matcher(hVar.c.b);
        return AbstractC0147y.e("https://firebaseremoteconfigrealtime.googleapis.com/v1/projects/", matcher.matches() ? matcher.group(1) : null, "/namespaces/", str, ":streamFetchInvalidations");
    }

    public final synchronized void e(long j) {
        try {
            if (a()) {
                int i = this.c;
                if (i > 0) {
                    this.c = i - 1;
                    this.g.schedule(new w(this, 15), j, TimeUnit.MILLISECONDS);
                } else if (!this.e) {
                    new FirebaseRemoteConfigClientException("Unable to connect to the server. Check your connection and try again.");
                    g();
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void g() {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            ((g) it2.next()).a();
        }
    }

    public final synchronized void h() {
        this.o.getClass();
        e(Math.max(0L, this.p.c().b.getTime() - new Date(System.currentTimeMillis()).getTime()));
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0097  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i(java.net.HttpURLConnection r7, java.lang.String r8, java.lang.String r9) {
        /*
            r6 = this;
            java.lang.String r0 = "POST"
            r7.setRequestMethod(r0)
            java.lang.String r0 = "X-Goog-Firebase-Installations-Auth"
            r7.setRequestProperty(r0, r9)
            com.google.firebase.h r9 = r6.i
            r9.a()
            com.google.firebase.i r0 = r9.c
            java.lang.String r1 = r0.a
            java.lang.String r2 = "X-Goog-Api-Key"
            r7.setRequestProperty(r2, r1)
            android.content.Context r1 = r6.l
            java.lang.String r2 = r1.getPackageName()
            java.lang.String r3 = "X-Android-Package"
            r7.setRequestProperty(r3, r2)
            java.lang.String r2 = "FirebaseRemoteConfig"
            java.lang.String r3 = "Could not get fingerprint hash for package: "
            r4 = 0
            java.lang.String r5 = r1.getPackageName()     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4c
            byte[] r5 = com.google.android.gms.common.util.c.i(r1, r5)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4c
            if (r5 != 0) goto L47
            java.lang.StringBuilder r5 = new java.lang.StringBuilder     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4c
            r5.<init>(r3)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4c
            java.lang.String r3 = r1.getPackageName()     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4c
            r5.append(r3)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4c
            java.lang.String r3 = r5.toString()     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4c
            android.util.Log.e(r2, r3)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4c
        L45:
            r1 = r4
            goto L62
        L47:
            java.lang.String r1 = com.google.android.gms.common.util.c.c(r5)     // Catch: android.content.pm.PackageManager.NameNotFoundException -> L4c
            goto L62
        L4c:
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            java.lang.String r5 = "No such package: "
            r3.<init>(r5)
            java.lang.String r1 = r1.getPackageName()
            r3.append(r1)
            java.lang.String r1 = r3.toString()
            android.util.Log.i(r2, r1)
            goto L45
        L62:
            java.lang.String r2 = "X-Android-Cert"
            r7.setRequestProperty(r2, r1)
            java.lang.String r1 = "X-Google-GFE-Can-Retry"
            java.lang.String r2 = "yes"
            r7.setRequestProperty(r1, r2)
            java.lang.String r1 = "X-Accept-Response-Streaming"
            java.lang.String r2 = "true"
            r7.setRequestProperty(r1, r2)
            java.lang.String r1 = "Content-Type"
            java.lang.String r2 = "application/json"
            r7.setRequestProperty(r1, r2)
            java.lang.String r1 = "Accept"
            r7.setRequestProperty(r1, r2)
            java.util.HashMap r1 = new java.util.HashMap
            r1.<init>()
            r9.a()
            java.lang.String r2 = r0.b
            java.util.regex.Pattern r3 = com.google.firebase.remoteconfig.internal.h.s
            java.util.regex.Matcher r2 = r3.matcher(r2)
            boolean r3 = r2.matches()
            if (r3 == 0) goto L9c
            r3 = 1
            java.lang.String r4 = r2.group(r3)
        L9c:
            java.lang.String r2 = "project"
            r1.put(r2, r4)
            java.lang.String r2 = "namespace"
            java.lang.String r3 = r6.m
            r1.put(r2, r3)
            com.google.firebase.remoteconfig.internal.e r2 = r6.h
            com.google.firebase.remoteconfig.internal.j r2 = r2.g
            android.content.SharedPreferences r2 = r2.a
            java.lang.String r3 = "last_template_version"
            r4 = 0
            long r2 = r2.getLong(r3, r4)
            java.lang.String r2 = java.lang.Long.toString(r2)
            java.lang.String r3 = "lastKnownVersionNumber"
            r1.put(r3, r2)
            r9.a()
            java.lang.String r9 = "appId"
            java.lang.String r0 = r0.b
            r1.put(r9, r0)
            java.lang.String r9 = "sdkVersion"
            java.lang.String r0 = "22.1.2"
            r1.put(r9, r0)
            java.lang.String r9 = "appInstanceId"
            r1.put(r9, r8)
            org.json.JSONObject r8 = new org.json.JSONObject
            r8.<init>(r1)
            java.lang.String r8 = r8.toString()
            java.lang.String r9 = "utf-8"
            byte[] r8 = r8.getBytes(r9)
            java.io.BufferedOutputStream r9 = new java.io.BufferedOutputStream
            java.io.OutputStream r7 = r7.getOutputStream()
            r9.<init>(r7)
            r9.write(r8)
            r9.flush()
            r9.close()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.remoteconfig.internal.h.i(java.net.HttpURLConnection, java.lang.String, java.lang.String):void");
    }

    public final synchronized com.onetrust.otpublishers.headless.UI.TVUI.datautils.d j(HttpURLConnection httpURLConnection) {
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar;
        g gVar = new g(this);
        e eVar = this.h;
        b bVar = this.k;
        LinkedHashSet linkedHashSet = this.a;
        ScheduledExecutorService scheduledExecutorService = this.g;
        dVar = new com.onetrust.otpublishers.headless.UI.TVUI.datautils.d();
        dVar.b = httpURLConnection;
        dVar.c = eVar;
        dVar.d = bVar;
        dVar.a = linkedHashSet;
        dVar.e = gVar;
        dVar.f = scheduledExecutorService;
        dVar.g = new Random();
        return dVar;
    }

    public final void k(Date date) {
        j jVar = this.p;
        int i = jVar.c().a + 1;
        jVar.e(i, new Date(date.getTime() + (TimeUnit.MINUTES.toMillis(r[(i < 8 ? i : 8) - 1]) / 2) + this.n.nextInt((int) r2)));
    }
}
