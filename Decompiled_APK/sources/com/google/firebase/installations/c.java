package com.google.firebase.installations;

import android.net.TrafficStats;
import android.util.Log;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.text.input.internal.u;
import com.google.android.gms.internal.ads.C2007ea;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.m;
import com.google.firebase.components.l;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c implements d {
    public static final Object m = new Object();
    public final com.google.firebase.h a;
    public final com.google.firebase.installations.remote.c b;
    public final u c;
    public final i d;
    public final l e;
    public final g f;
    public final Object g;
    public final ExecutorService h;
    public final com.google.firebase.concurrent.i i;
    public String j;
    public final HashSet k;
    public final ArrayList l;

    static {
        new AtomicInteger(1);
    }

    public c(com.google.firebase.h hVar, com.google.firebase.inject.b bVar, ExecutorService executorService, com.google.firebase.concurrent.i iVar) {
        hVar.a();
        com.google.firebase.installations.remote.c cVar = new com.google.firebase.installations.remote.c(hVar.a, bVar);
        u uVar = new u(hVar, 13);
        if (retrofit2.adapter.rxjava3.d.c == null) {
            retrofit2.adapter.rxjava3.d.c = new retrofit2.adapter.rxjava3.d(18);
        }
        retrofit2.adapter.rxjava3.d dVar = retrofit2.adapter.rxjava3.d.c;
        if (i.d == null) {
            i.d = new i(dVar);
        }
        i iVar2 = i.d;
        l lVar = new l(new com.google.firebase.components.c(hVar, 2));
        g gVar = new g();
        this.g = new Object();
        this.k = new HashSet();
        this.l = new ArrayList();
        this.a = hVar;
        this.b = cVar;
        this.c = uVar;
        this.d = iVar2;
        this.e = lVar;
        this.f = gVar;
        this.h = executorService;
        this.i = iVar;
    }

    /* JADX WARN: Finally extract failed */
    public final void a() {
        com.google.firebase.installations.local.a aVarO;
        synchronized (m) {
            try {
                com.google.firebase.h hVar = this.a;
                hVar.a();
                com.quizlet.data.repository.widget.b bVarA = com.quizlet.data.repository.widget.b.a(hVar.a);
                try {
                    aVarO = this.c.o();
                    int i = aVarO.b;
                    boolean z = true;
                    if (i != 2 && i != 1) {
                        z = false;
                    }
                    if (z) {
                        String strF = f(aVarO);
                        u uVar = this.c;
                        C2007ea c2007eaA = aVarO.a();
                        c2007eaA.a = strF;
                        c2007eaA.b = 3;
                        aVarO = c2007eaA.j();
                        uVar.k(aVarO);
                    }
                    if (bVarA != null) {
                        bVarA.s();
                    }
                } catch (Throwable th) {
                    if (bVarA != null) {
                        bVarA.s();
                    }
                    throw th;
                }
            } catch (Throwable th2) {
                throw th2;
            }
        }
        i(aVarO);
        this.i.execute(new b(this, 2));
    }

    public final com.google.firebase.installations.local.a b(com.google.firebase.installations.local.a aVar) throws FirebaseInstallationsException {
        int responseCode;
        com.google.firebase.installations.remote.b bVarF;
        com.google.firebase.h hVar = this.a;
        hVar.a();
        String str = hVar.c.a;
        String str2 = aVar.a;
        com.google.firebase.h hVar2 = this.a;
        hVar2.a();
        String str3 = hVar2.c.g;
        String str4 = aVar.d;
        com.google.firebase.installations.remote.c cVar = this.b;
        com.google.firebase.installations.remote.d dVar = cVar.c;
        if (!dVar.a()) {
            throw new FirebaseInstallationsException("Firebase Installations Service is unavailable. Please try again later.");
        }
        URL urlA = com.google.firebase.installations.remote.c.a("projects/" + str3 + "/installations/" + str2 + "/authTokens:generate");
        for (int i = 0; i <= 1; i++) {
            TrafficStats.setThreadStatsTag(32771);
            HttpURLConnection httpURLConnectionC = cVar.c(urlA, str);
            try {
                try {
                    httpURLConnectionC.setRequestMethod("POST");
                    httpURLConnectionC.addRequestProperty("Authorization", "FIS_v2 " + str4);
                    httpURLConnectionC.setDoOutput(true);
                    com.google.firebase.installations.remote.c.h(httpURLConnectionC);
                    responseCode = httpURLConnectionC.getResponseCode();
                    dVar.b(responseCode);
                } catch (Throwable th) {
                    httpURLConnectionC.disconnect();
                    TrafficStats.clearThreadStatsTag();
                    throw th;
                }
            } catch (IOException | AssertionError unused) {
            }
            if (responseCode >= 200 && responseCode < 300) {
                bVarF = com.google.firebase.installations.remote.c.f(httpURLConnectionC);
            } else {
                com.google.firebase.installations.remote.c.b(httpURLConnectionC, null, str, str3);
                if (responseCode == 401 || responseCode == 404) {
                    C0122z c0122zA = com.google.firebase.installations.remote.b.a();
                    c0122zA.b = 3;
                    bVarF = c0122zA.e();
                } else {
                    if (responseCode == 429) {
                        throw new FirebaseInstallationsException("Firebase servers have received too many requests from this client in a short period of time. Please try again later.");
                    }
                    if (responseCode < 500 || responseCode >= 600) {
                        Log.e("Firebase-Installations", "Firebase Installations can not communicate with Firebase server APIs due to invalid configuration. Please update your Firebase initialization process and set valid Firebase options (API key, Project ID, Application ID) when initializing Firebase.");
                        C0122z c0122zA2 = com.google.firebase.installations.remote.b.a();
                        c0122zA2.b = 2;
                        bVarF = c0122zA2.e();
                    }
                    httpURLConnectionC.disconnect();
                    TrafficStats.clearThreadStatsTag();
                }
            }
            httpURLConnectionC.disconnect();
            TrafficStats.clearThreadStatsTag();
            int iK = AbstractC0147y.k(bVarF.c);
            if (iK == 0) {
                i iVar = this.d;
                iVar.getClass();
                TimeUnit timeUnit = TimeUnit.MILLISECONDS;
                iVar.a.getClass();
                long seconds = timeUnit.toSeconds(System.currentTimeMillis());
                C2007ea c2007eaA = aVar.a();
                c2007eaA.c = bVarF.a;
                c2007eaA.e = Long.valueOf(bVarF.b);
                c2007eaA.f = Long.valueOf(seconds);
                return c2007eaA.j();
            }
            if (iK == 1) {
                C2007ea c2007eaA2 = aVar.a();
                c2007eaA2.g = "BAD CONFIG";
                c2007eaA2.b = 5;
                return c2007eaA2.j();
            }
            if (iK != 2) {
                throw new FirebaseInstallationsException("Firebase Installations Service is unavailable. Please try again later.");
            }
            synchronized (this) {
                this.j = null;
            }
            C2007ea c2007eaA3 = aVar.a();
            c2007eaA3.b = 2;
            return c2007eaA3.j();
        }
        throw new FirebaseInstallationsException("Firebase Installations Service is unavailable. Please try again later.");
    }

    public final m c() {
        String str;
        e();
        synchronized (this) {
            str = this.j;
        }
        if (str != null) {
            return S3.i(str);
        }
        com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
        f fVar2 = new f(fVar);
        synchronized (this.g) {
            this.l.add(fVar2);
        }
        m mVar = fVar.a;
        this.h.execute(new b(this, 0));
        return mVar;
    }

    public final m d() {
        e();
        com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
        e eVar = new e(this.d, fVar);
        synchronized (this.g) {
            this.l.add(eVar);
        }
        this.h.execute(new b(this, 1));
        return fVar.a;
    }

    public final void e() {
        com.google.firebase.h hVar = this.a;
        hVar.a();
        com.google.android.gms.common.internal.u.f(hVar.c.b, "Please set your Application ID. A valid Firebase App ID is required to communicate with Firebase server APIs: It identifies your application with Firebase.Please refer to https://firebase.google.com/support/privacy/init-options.");
        hVar.a();
        com.google.android.gms.common.internal.u.f(hVar.c.g, "Please set your Project ID. A valid Firebase Project ID is required to communicate with Firebase server APIs: It identifies your application with Firebase.Please refer to https://firebase.google.com/support/privacy/init-options.");
        hVar.a();
        com.google.android.gms.common.internal.u.f(hVar.c.a, "Please set a valid API key. A Firebase API key is required to communicate with Firebase server APIs: It authenticates your project with Google.Please refer to https://firebase.google.com/support/privacy/init-options.");
        hVar.a();
        String str = hVar.c.b;
        Pattern pattern = i.c;
        com.google.android.gms.common.internal.u.a("Please set your Application ID. A valid Firebase App ID is required to communicate with Firebase server APIs: It identifies your application with Firebase.Please refer to https://firebase.google.com/support/privacy/init-options.", str.contains(":"));
        hVar.a();
        com.google.android.gms.common.internal.u.a("Please set a valid API key. A Firebase API key is required to communicate with Firebase server APIs: It authenticates your project with Google.Please refer to https://firebase.google.com/support/privacy/init-options.", i.c.matcher(hVar.c.a).matches());
    }

    /* JADX WARN: Removed duplicated region for block: B:6:0x001e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String f(com.google.firebase.installations.local.a r6) {
        /*
            r5 = this;
            com.google.firebase.h r0 = r5.a
            r0.a()
            java.lang.String r0 = r0.b
            java.lang.String r1 = "CHIME_ANDROID_SDK"
            boolean r0 = r0.equals(r1)
            if (r0 != 0) goto L1e
            com.google.firebase.h r0 = r5.a
            r0.a()
            java.lang.String r1 = "[DEFAULT]"
            java.lang.String r0 = r0.b
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L5c
        L1e:
            r0 = 1
            int r6 = r6.b
            if (r6 != r0) goto L5c
            com.google.firebase.components.l r6 = r5.e
            java.lang.Object r6 = r6.get()
            com.google.firebase.installations.local.b r6 = (com.google.firebase.installations.local.b) r6
            android.content.SharedPreferences r0 = r6.a
            monitor-enter(r0)
            android.content.SharedPreferences r1 = r6.a     // Catch: java.lang.Throwable -> L3f
            monitor-enter(r1)     // Catch: java.lang.Throwable -> L3f
            android.content.SharedPreferences r2 = r6.a     // Catch: java.lang.Throwable -> L57
            java.lang.String r3 = "|S|id"
            r4 = 0
            java.lang.String r2 = r2.getString(r3, r4)     // Catch: java.lang.Throwable -> L57
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L57
            if (r2 == 0) goto L41
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L3f
            goto L46
        L3f:
            r6 = move-exception
            goto L5a
        L41:
            java.lang.String r2 = r6.a()     // Catch: java.lang.Throwable -> L3f
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L3f
        L46:
            boolean r6 = android.text.TextUtils.isEmpty(r2)
            if (r6 == 0) goto L56
            com.google.firebase.installations.g r6 = r5.f
            r6.getClass()
            java.lang.String r6 = com.google.firebase.installations.g.a()
            return r6
        L56:
            return r2
        L57:
            r6 = move-exception
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L57
            throw r6     // Catch: java.lang.Throwable -> L3f
        L5a:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L3f
            throw r6
        L5c:
            com.google.firebase.installations.g r6 = r5.f
            r6.getClass()
            java.lang.String r6 = com.google.firebase.installations.g.a()
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.installations.c.f(com.google.firebase.installations.local.a):java.lang.String");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v2, types: [com.google.firebase.installations.remote.c] */
    /* JADX WARN: Type inference failed for: r2v22 */
    /* JADX WARN: Type inference failed for: r2v23 */
    /* JADX WARN: Type inference failed for: r2v24 */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r2v4 */
    /* JADX WARN: Type inference failed for: r2v6 */
    /* JADX WARN: Type inference failed for: r2v7, types: [com.google.firebase.installations.remote.a] */
    public final com.google.firebase.installations.local.a g(com.google.firebase.installations.local.a aVar) throws FirebaseInstallationsException {
        int responseCode;
        String str = aVar.a;
        String string = null;
        if (str != null && str.length() == 11) {
            com.google.firebase.installations.local.b bVar = (com.google.firebase.installations.local.b) this.e.get();
            synchronized (bVar.a) {
                try {
                    String[] strArr = com.google.firebase.installations.local.b.c;
                    int i = 0;
                    while (true) {
                        if (i < 4) {
                            String str2 = strArr[i];
                            String string2 = bVar.a.getString("|T|" + bVar.b + "|" + str2, null);
                            if (string2 == null || string2.isEmpty()) {
                                i++;
                            } else if (string2.startsWith("{")) {
                                try {
                                    string = new JSONObject(string2).getString("token");
                                } catch (JSONException unused) {
                                }
                            } else {
                                string = string2;
                            }
                        }
                    }
                } finally {
                }
            }
        }
        com.google.firebase.installations.remote.c cVar = this.b;
        com.google.firebase.h hVar = this.a;
        hVar.a();
        String str3 = hVar.c.a;
        String str4 = aVar.a;
        com.google.firebase.h hVar2 = this.a;
        hVar2.a();
        String str5 = hVar2.c.g;
        com.google.firebase.h hVar3 = this.a;
        hVar3.a();
        String str6 = hVar3.c.b;
        com.google.firebase.installations.remote.d dVar = cVar.c;
        if (!dVar.a()) {
            throw new FirebaseInstallationsException("Firebase Installations Service is unavailable. Please try again later.");
        }
        URL urlA = com.google.firebase.installations.remote.c.a("projects/" + str5 + "/installations");
        int i2 = 0;
        com.google.firebase.installations.remote.a aVar2 = cVar;
        while (i2 <= 1) {
            TrafficStats.setThreadStatsTag(32769);
            HttpURLConnection httpURLConnectionC = aVar2.c(urlA, str3);
            try {
                try {
                    httpURLConnectionC.setRequestMethod("POST");
                    httpURLConnectionC.setDoOutput(true);
                    if (string != null) {
                        httpURLConnectionC.addRequestProperty("x-goog-fis-android-iid-migration-auth", string);
                    }
                    com.google.firebase.installations.remote.c.g(httpURLConnectionC, str4, str6);
                    responseCode = httpURLConnectionC.getResponseCode();
                    dVar.b(responseCode);
                } catch (IOException | AssertionError unused2) {
                }
                if (responseCode >= 200 && responseCode < 300) {
                    com.google.firebase.installations.remote.a aVarE = com.google.firebase.installations.remote.c.e(httpURLConnectionC);
                    httpURLConnectionC.disconnect();
                    TrafficStats.clearThreadStatsTag();
                    aVar2 = aVarE;
                } else {
                    try {
                        com.google.firebase.installations.remote.c.b(httpURLConnectionC, str6, str3, str5);
                    } catch (IOException | AssertionError unused3) {
                        httpURLConnectionC.disconnect();
                        TrafficStats.clearThreadStatsTag();
                        i2++;
                        aVar2 = aVar2;
                    }
                    if (responseCode == 429) {
                        throw new FirebaseInstallationsException("Firebase servers have received too many requests from this client in a short period of time. Please try again later.");
                    }
                    if (responseCode < 500 || responseCode >= 600) {
                        Log.e("Firebase-Installations", "Firebase Installations can not communicate with Firebase server APIs due to invalid configuration. Please update your Firebase initialization process and set valid Firebase options (API key, Project ID, Application ID) when initializing Firebase.");
                        com.google.firebase.installations.remote.a aVar3 = new com.google.firebase.installations.remote.a(null, null, null, null, 2);
                        httpURLConnectionC.disconnect();
                        TrafficStats.clearThreadStatsTag();
                        aVar2 = aVar3;
                    } else {
                        httpURLConnectionC.disconnect();
                        TrafficStats.clearThreadStatsTag();
                        i2++;
                        aVar2 = aVar2;
                    }
                }
                int iK = AbstractC0147y.k(aVar2.e);
                if (iK != 0) {
                    if (iK != 1) {
                        throw new FirebaseInstallationsException("Firebase Installations Service is unavailable. Please try again later.");
                    }
                    C2007ea c2007eaA = aVar.a();
                    c2007eaA.g = "BAD CONFIG";
                    c2007eaA.b = 5;
                    return c2007eaA.j();
                }
                String str7 = aVar2.b;
                String str8 = aVar2.c;
                i iVar = this.d;
                iVar.getClass();
                TimeUnit timeUnit = TimeUnit.MILLISECONDS;
                iVar.a.getClass();
                long seconds = timeUnit.toSeconds(System.currentTimeMillis());
                com.google.firebase.installations.remote.b bVar2 = aVar2.d;
                String str9 = bVar2.a;
                long j = bVar2.b;
                C2007ea c2007eaA2 = aVar.a();
                c2007eaA2.a = str7;
                c2007eaA2.b = 4;
                c2007eaA2.c = str9;
                c2007eaA2.d = str8;
                c2007eaA2.e = Long.valueOf(j);
                c2007eaA2.f = Long.valueOf(seconds);
                return c2007eaA2.j();
            } finally {
                httpURLConnectionC.disconnect();
                TrafficStats.clearThreadStatsTag();
            }
        }
        throw new FirebaseInstallationsException("Firebase Installations Service is unavailable. Please try again later.");
    }

    public final void h(Exception exc) {
        synchronized (this.g) {
            try {
                Iterator it2 = this.l.iterator();
                while (it2.hasNext()) {
                    if (((h) it2.next()).b(exc)) {
                        it2.remove();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void i(com.google.firebase.installations.local.a aVar) {
        synchronized (this.g) {
            try {
                Iterator it2 = this.l.iterator();
                while (it2.hasNext()) {
                    if (((h) it2.next()).a(aVar)) {
                        it2.remove();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
