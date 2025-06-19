package com.google.android.gms.internal.ads;

import android.net.TrafficStats;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;
import java.util.concurrent.PriorityBlockingQueue;

/* renamed from: com.google.android.gms.internal.ads.z3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2898z3 extends Thread {
    public final PriorityBlockingQueue a;
    public final C1732Mb b;
    public final com.android.volley.toolbox.d c;
    public volatile boolean d = false;
    public final S4 e;

    public C2898z3(PriorityBlockingQueue priorityBlockingQueue, C1732Mb c1732Mb, com.android.volley.toolbox.d dVar, S4 s4) {
        this.a = priorityBlockingQueue;
        this.b = c1732Mb;
        this.c = dVar;
        this.e = s4;
    }

    public final void a() {
        S4 s4 = this.e;
        B3 b3 = (B3) this.a.take();
        SystemClock.elapsedRealtime();
        b3.i();
        Object obj = null;
        try {
            try {
                b3.d("network-queue-take");
                synchronized (b3.e) {
                }
                TrafficStats.setThreadStatsTag(b3.d);
                A3 a3F = this.b.f(b3);
                b3.d("network-http-complete");
                if (a3F.e && b3.j()) {
                    b3.f("not-modified");
                    b3.g();
                } else {
                    androidx.browser.customtabs.k kVarA = b3.a(a3F);
                    b3.d("network-parse-complete");
                    C2683u3 c2683u3 = (C2683u3) kVarA.c;
                    if (c2683u3 != null) {
                        this.c.r(b3.b(), c2683u3);
                        b3.d("network-cache-written");
                    }
                    synchronized (b3.e) {
                        b3.i = true;
                    }
                    s4.g(b3, kVarA, null);
                    b3.h(kVarA);
                }
            } catch (zzaqd e) {
                SystemClock.elapsedRealtime();
                s4.getClass();
                b3.d("post-error");
                ((ExecutorC2769w3) s4.b).b.post(new C(b3, new androidx.browser.customtabs.k(e), obj, 1));
                b3.g();
            } catch (Exception e2) {
                Log.e("Volley", H3.c("Unhandled exception %s", e2.toString()), e2);
                zzaqd zzaqdVar = new zzaqd(e2);
                SystemClock.elapsedRealtime();
                s4.getClass();
                b3.d("post-error");
                ((ExecutorC2769w3) s4.b).b.post(new C(b3, new androidx.browser.customtabs.k(zzaqdVar), obj, 1));
                b3.g();
            }
            b3.i();
        } catch (Throwable th) {
            b3.i();
            throw th;
        }
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public final void run() throws SecurityException, IllegalArgumentException {
        Process.setThreadPriority(10);
        while (true) {
            try {
                a();
            } catch (InterruptedException unused) {
                if (this.d) {
                    Thread.currentThread().interrupt();
                    return;
                }
                H3.a("Ignoring spurious interrupt of NetworkDispatcher thread; use quit() to terminate it", new Object[0]);
            }
        }
    }
}
