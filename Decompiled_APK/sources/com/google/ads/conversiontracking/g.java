package com.google.ads.conversiontracking;

import android.app.ActivityManager;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.PowerManager;
import android.os.Process;
import android.util.Log;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class g implements Runnable {
    public static final long k;
    public static final long l;
    public static final Object m;
    public static g n;
    public final long a;
    public final long b;
    public final f c;
    public final Context d;
    public final SharedPreferences h;
    public long i;
    public final Handler j;
    public final Object e = new Object();
    public final HashMap g = new HashMap();
    public final HashSet f = new HashSet();

    static {
        TimeUnit timeUnit = TimeUnit.SECONDS;
        k = timeUnit.toMillis(3600L);
        l = timeUnit.toMillis(30L);
        m = new Object();
    }

    public g(Context context, long j, long j2, f fVar) {
        this.d = context;
        this.b = j;
        this.a = j2;
        this.c = fVar;
        SharedPreferences sharedPreferences = context.getSharedPreferences("google_auto_usage", 0);
        this.h = sharedPreferences;
        if (this.i == 0) {
            HashMap map = r.a;
            this.i = sharedPreferences.getLong("end_of_interval", System.currentTimeMillis() + j);
        }
        HandlerThread handlerThread = new HandlerThread("Google Conversion SDK", 10);
        handlerThread.start();
        this.j = new Handler(handlerThread.getLooper());
        e();
    }

    public static g a(Context context) {
        synchronized (m) {
            if (n == null) {
                try {
                    n = new g(context, k, l, new f(context));
                } catch (Exception e) {
                    Log.e("GoogleConversionReporter", "Error starting automated usage thread", e);
                }
            }
        }
        return n;
    }

    public final void b(long j) {
        synchronized (this.e) {
            try {
                Handler handler = this.j;
                if (handler != null) {
                    handler.removeCallbacks(this);
                    this.j.postDelayed(this, j);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final long c() {
        HashMap map = r.a;
        long jCurrentTimeMillis = System.currentTimeMillis();
        long j = this.i;
        long j2 = this.b;
        return ((jCurrentTimeMillis >= j ? ((jCurrentTimeMillis - j) / j2) + 1 : 0L) * j2) + j;
    }

    public final void d() {
        synchronized (this.e) {
            try {
                if (!this.f.contains("943230862") && !this.g.containsKey("943230862")) {
                    this.c.c("943230862", this.i);
                    this.g.put("943230862", Long.valueOf(this.i));
                }
            } finally {
            }
        }
    }

    public final void e() {
        synchronized (this.e) {
            long jC = c();
            HashMap map = r.a;
            b(jC - System.currentTimeMillis());
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        Context context = this.d;
        ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
        KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService("keyguard");
        PowerManager powerManager = (PowerManager) context.getSystemService("power");
        List<ActivityManager.RunningAppProcessInfo> runningAppProcesses = activityManager.getRunningAppProcesses();
        if (runningAppProcesses != null) {
            for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : runningAppProcesses) {
                if (Process.myPid() == runningAppProcessInfo.pid && runningAppProcessInfo.importance == 100 && !keyguardManager.inKeyguardRestrictedInputMode() && powerManager.isScreenOn()) {
                    synchronized (this.e) {
                        try {
                            for (Map.Entry entry : this.g.entrySet()) {
                                String str = (String) entry.getKey();
                                long jLongValue = ((Long) entry.getValue()).longValue();
                                long j = this.i;
                                if (jLongValue < j) {
                                    entry.setValue(Long.valueOf(j));
                                    this.c.c(str, this.i);
                                }
                            }
                        } catch (Throwable th) {
                            throw th;
                        }
                    }
                    e();
                    long jC = c();
                    this.h.edit().putLong("end_of_interval", jC).commit();
                    this.i = jC;
                    return;
                }
            }
        }
        b(this.a);
    }
}
