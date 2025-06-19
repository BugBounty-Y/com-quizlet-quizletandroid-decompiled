package com.google.firebase.crashlytics.internal.send;

import android.os.SystemClock;
import android.util.Log;
import com.google.android.datatransport.d;
import com.google.android.datatransport.g;
import com.google.android.datatransport.runtime.p;
import com.google.android.gms.tasks.f;
import com.google.firebase.crashlytics.internal.common.i;
import com.google.firebase.crashlytics.internal.common.x;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class c {
    public final double a;
    public final double b;
    public final long c;
    public final long d;
    public final int e;
    public final ArrayBlockingQueue f;
    public final ThreadPoolExecutor g;
    public final p h;
    public final com.quizlet.data.repository.explanations.myexplanations.a i;
    public int j;
    public long k;

    public c(p pVar, com.google.firebase.crashlytics.internal.settings.a aVar, com.quizlet.data.repository.explanations.myexplanations.a aVar2) {
        double d = aVar.d;
        this.a = d;
        this.b = aVar.e;
        this.c = aVar.f * 1000;
        this.h = pVar;
        this.i = aVar2;
        this.d = SystemClock.elapsedRealtime();
        int i = (int) d;
        this.e = i;
        ArrayBlockingQueue arrayBlockingQueue = new ArrayBlockingQueue(i);
        this.f = arrayBlockingQueue;
        this.g = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, arrayBlockingQueue);
        this.j = 0;
        this.k = 0L;
    }

    public final int a() {
        if (this.k == 0) {
            this.k = System.currentTimeMillis();
        }
        int iCurrentTimeMillis = (int) ((System.currentTimeMillis() - this.k) / this.c);
        int iMin = this.f.size() == this.e ? Math.min(100, this.j + iCurrentTimeMillis) : Math.max(0, this.j - iCurrentTimeMillis);
        if (this.j != iMin) {
            this.j = iMin;
            this.k = System.currentTimeMillis();
        }
        return iMin;
    }

    public final void b(final com.google.firebase.crashlytics.internal.common.a aVar, final f fVar) {
        Log.isLoggable("FirebaseCrashlytics", 3);
        final boolean z = SystemClock.elapsedRealtime() - this.d < 2000;
        this.h.a(new com.google.android.datatransport.a(aVar.a, d.c, null), new g() { // from class: com.google.firebase.crashlytics.internal.send.b
            @Override // com.google.android.datatransport.g
            public final void b(Exception exc) throws Throwable {
                c cVar = this.a;
                cVar.getClass();
                f fVar2 = fVar;
                if (exc != null) {
                    fVar2.c(exc);
                    return;
                }
                if (z) {
                    boolean z2 = true;
                    CountDownLatch countDownLatch = new CountDownLatch(1);
                    new Thread(new i(4, cVar, countDownLatch)).start();
                    TimeUnit timeUnit = TimeUnit.SECONDS;
                    ExecutorService executorService = x.a;
                    boolean z3 = false;
                    try {
                        long nanos = timeUnit.toNanos(2L);
                        long jNanoTime = System.nanoTime() + nanos;
                        while (true) {
                            try {
                                try {
                                    countDownLatch.await(nanos, TimeUnit.NANOSECONDS);
                                    break;
                                } catch (Throwable th) {
                                    th = th;
                                    if (z2) {
                                        Thread.currentThread().interrupt();
                                    }
                                    throw th;
                                }
                            } catch (InterruptedException unused) {
                                nanos = jNanoTime - System.nanoTime();
                                z3 = true;
                            }
                        }
                        if (z3) {
                            Thread.currentThread().interrupt();
                        }
                    } catch (Throwable th2) {
                        th = th2;
                        z2 = z3;
                    }
                }
                fVar2.d(aVar);
            }
        });
    }
}
