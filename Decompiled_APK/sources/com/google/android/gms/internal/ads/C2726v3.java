package com.google.android.gms.internal.ads;

import android.os.Process;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.PriorityBlockingQueue;

/* renamed from: com.google.android.gms.internal.ads.v3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2726v3 extends Thread {
    public static final boolean g = H3.a;
    public final PriorityBlockingQueue a;
    public final PriorityBlockingQueue b;
    public final com.android.volley.toolbox.d c;
    public volatile boolean d = false;
    public final com.quizlet.data.repository.explanations.textbook.a e;
    public final S4 f;

    public C2726v3(PriorityBlockingQueue priorityBlockingQueue, PriorityBlockingQueue priorityBlockingQueue2, com.android.volley.toolbox.d dVar, S4 s4) {
        this.a = priorityBlockingQueue;
        this.b = priorityBlockingQueue2;
        this.c = dVar;
        this.f = s4;
        com.quizlet.data.repository.explanations.textbook.a aVar = new com.quizlet.data.repository.explanations.textbook.a();
        aVar.a = new HashMap();
        aVar.d = s4;
        aVar.b = this;
        aVar.c = priorityBlockingQueue2;
        this.e = aVar;
    }

    public final void a() {
        B3 b3 = (B3) this.a.take();
        b3.d("cache-queue-take");
        b3.i();
        try {
            synchronized (b3.e) {
            }
            com.android.volley.toolbox.d dVar = this.c;
            C2683u3 c2683u3P = dVar.p(b3.b());
            if (c2683u3P == null) {
                b3.d("cache-miss");
                if (!this.e.k(b3)) {
                    this.b.put(b3);
                }
            } else {
                long jCurrentTimeMillis = System.currentTimeMillis();
                if (c2683u3P.e < jCurrentTimeMillis) {
                    b3.d("cache-hit-expired");
                    b3.j = c2683u3P;
                    if (!this.e.k(b3)) {
                        this.b.put(b3);
                    }
                } else {
                    b3.d("cache-hit");
                    byte[] bArr = c2683u3P.a;
                    Map map = c2683u3P.g;
                    androidx.browser.customtabs.k kVarA = b3.a(new A3(200, bArr, map, A3.a(map), false));
                    b3.d("cache-hit-parsed");
                    if (!(((zzaqd) kVarA.d) == null)) {
                        b3.d("cache-parsing-failed");
                        String strB = b3.b();
                        synchronized (dVar) {
                            try {
                                C2683u3 c2683u3P2 = dVar.p(strB);
                                if (c2683u3P2 != null) {
                                    c2683u3P2.f = 0L;
                                    c2683u3P2.e = 0L;
                                    dVar.r(strB, c2683u3P2);
                                }
                            } finally {
                            }
                        }
                        b3.j = null;
                        if (!this.e.k(b3)) {
                            this.b.put(b3);
                        }
                    } else if (c2683u3P.f < jCurrentTimeMillis) {
                        b3.d("cache-hit-refresh-needed");
                        b3.j = c2683u3P;
                        kVarA.a = true;
                        if (this.e.k(b3)) {
                            this.f.g(b3, kVarA, null);
                        } else {
                            this.f.g(b3, kVarA, new Qv(this, false, b3, 3));
                        }
                    } else {
                        this.f.g(b3, kVarA, null);
                    }
                }
            }
            b3.i();
        } catch (Throwable th) {
            b3.i();
            throw th;
        }
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public final void run() throws SecurityException, IllegalArgumentException {
        if (g) {
            H3.b("start new dispatcher", new Object[0]);
        }
        Process.setThreadPriority(10);
        this.c.q();
        while (true) {
            try {
                a();
            } catch (InterruptedException unused) {
                if (this.d) {
                    Thread.currentThread().interrupt();
                    return;
                }
                H3.a("Ignoring spurious interrupt of CacheDispatcher thread; use quit() to terminate it", new Object[0]);
            }
        }
    }
}
