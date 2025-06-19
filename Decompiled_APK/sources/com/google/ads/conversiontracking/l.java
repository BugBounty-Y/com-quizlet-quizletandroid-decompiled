package com.google.ads.conversiontracking;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import androidx.appcompat.app.J;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class l {
    public final Context c;
    public final o f;
    public final Object a = new Object();
    public boolean d = true;
    public boolean e = false;
    public final LinkedList b = new LinkedList();

    public l(Context context) {
        this.c = context;
        this.f = new o(context);
        new Thread(new i(this)).start();
        ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        HashMap map = r.a;
        long j = (context.getSharedPreferences("google_conversion", 0).getLong("last_retry_time", 0L) + 300000) - System.currentTimeMillis();
        scheduledThreadPoolExecutor.scheduleAtFixedRate(new J(this, 17), j <= 0 ? 0L : j, 300000L, TimeUnit.MILLISECONDS);
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x0074, code lost:
    
        r4 = new java.lang.StringBuilder(33);
        r4.append("Receive response code ");
        r4.append(r3);
        android.util.Log.i("GoogleConversionReporter", r4.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x008d, code lost:
    
        if (200 > r3) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x008f, code lost:
    
        if (r3 >= 300) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0091, code lost:
    
        r6 = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0092, code lost:
    
        if (r6 != 2) goto L30;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0094, code lost:
    
        c(r10);
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0097, code lost:
    
        r0.disconnect();
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x009a, code lost:
    
        return r6;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int a(com.google.ads.conversiontracking.h r10) throws java.lang.Throwable {
        /*
            r9 = this;
            java.lang.String r0 = r10.g
            java.lang.String r1 = java.lang.String.valueOf(r0)
            int r2 = r1.length()
            java.lang.String r3 = "Pinging: "
            if (r2 == 0) goto L13
            java.lang.String r1 = r3.concat(r1)
            goto L18
        L13:
            java.lang.String r1 = new java.lang.String
            r1.<init>(r3)
        L18:
            java.lang.String r2 = "GoogleConversionReporter"
            android.util.Log.i(r2, r1)
            r1 = 0
            r3 = 0
            r4 = r1
        L20:
            r5 = 5
            r6 = 1
            if (r4 >= r5) goto Laf
            java.net.URL r5 = new java.net.URL     // Catch: java.lang.Throwable -> L9b java.io.IOException -> L9d
            r5.<init>(r0)     // Catch: java.lang.Throwable -> L9b java.io.IOException -> L9d
            java.net.URLConnection r0 = r5.openConnection()     // Catch: java.lang.Throwable -> L9b java.io.IOException -> L9d
            java.lang.Object r0 = com.google.firebase.perf.network.FirebasePerfUrlConnection.instrument(r0)     // Catch: java.lang.Throwable -> L9b java.io.IOException -> L9d
            java.net.URLConnection r0 = (java.net.URLConnection) r0     // Catch: java.lang.Throwable -> L9b java.io.IOException -> L9d
            java.net.HttpURLConnection r0 = (java.net.HttpURLConnection) r0     // Catch: java.lang.Throwable -> L9b java.io.IOException -> L9d
            r0.setInstanceFollowRedirects(r1)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            r3 = 60000(0xea60, float:8.4078E-41)
            r0.setConnectTimeout(r3)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            r0.setReadTimeout(r3)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            r0.setUseCaches(r1)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            int r3 = r0.getResponseCode()     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            r5 = 300(0x12c, float:4.2E-43)
            if (r5 > r3) goto L74
            r7 = 400(0x190, float:5.6E-43)
            if (r3 >= r7) goto L74
            java.lang.String r3 = "Location"
            java.lang.String r3 = r0.getHeaderField(r3)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            boolean r5 = android.text.TextUtils.isEmpty(r3)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            if (r5 == 0) goto L6b
            java.lang.String r10 = "Unable to follow redirect, no Location header."
            android.util.Log.i(r2, r10)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            r0.disconnect()
            return r1
        L65:
            r10 = move-exception
            r3 = r0
            goto La9
        L68:
            r10 = move-exception
            r3 = r0
            goto L9e
        L6b:
            r0.disconnect()
            int r4 = r4 + 1
            r8 = r3
            r3 = r0
            r0 = r8
            goto L20
        L74:
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            r7 = 33
            r4.<init>(r7)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            java.lang.String r7 = "Receive response code "
            r4.append(r7)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            r4.append(r3)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            java.lang.String r4 = r4.toString()     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            android.util.Log.i(r2, r4)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
            r4 = 200(0xc8, float:2.8E-43)
            r7 = 2
            if (r4 > r3) goto L92
            if (r3 >= r5) goto L92
            r6 = r7
        L92:
            if (r6 != r7) goto L97
            r9.c(r10)     // Catch: java.lang.Throwable -> L65 java.io.IOException -> L68
        L97:
            r0.disconnect()
            return r6
        L9b:
            r10 = move-exception
            goto La9
        L9d:
            r10 = move-exception
        L9e:
            java.lang.String r0 = "Error sending ping"
            android.util.Log.e(r2, r0, r10)     // Catch: java.lang.Throwable -> L9b
            if (r3 == 0) goto La8
            r3.disconnect()
        La8:
            return r1
        La9:
            if (r3 == 0) goto Lae
            r3.disconnect()
        Lae:
            throw r10
        Laf:
            java.lang.String r10 = "Ping failed; too many redirects."
            android.util.Log.e(r2, r10)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.ads.conversiontracking.l.a(com.google.ads.conversiontracking.h):int");
    }

    public final void b(String str, q qVar, boolean z, boolean z2, boolean z3) {
        NetworkInfo activeNetworkInfo;
        boolean z4 = false;
        h hVar = new h(str, qVar, z, z2);
        synchronized (this.a) {
            try {
                if (!z3) {
                    new Thread(new androidx.camera.core.impl.utils.futures.h(this, z4, hVar, 13)).start();
                    return;
                }
                this.f.f(hVar);
                if (this.e) {
                    Context context = this.c;
                    HashMap map = r.a;
                    ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
                    if (connectivityManager == null || ((activeNetworkInfo = connectivityManager.getActiveNetworkInfo()) != null && activeNetworkInfo.isConnected())) {
                        z4 = true;
                    }
                    if (z4) {
                        this.b.add(hVar);
                        this.d = true;
                        this.a.notify();
                    }
                }
            } finally {
            }
        }
    }

    public final void c(h hVar) {
        if (hVar.b || !hVar.a) {
            return;
        }
        HashMap map = r.a;
        SharedPreferences.Editor editorEdit = this.c.getSharedPreferences(hVar.e, 0).edit();
        editorEdit.putBoolean(hVar.f, true);
        editorEdit.commit();
    }
}
