package com.android.volley;

import android.os.Process;
import java.util.HashMap;
import java.util.concurrent.BlockingQueue;

/* loaded from: classes.dex */
public final class c extends Thread {
    public static final boolean g = y.a;
    public final BlockingQueue a;
    public final BlockingQueue b;
    public final b c;
    public final u d;
    public volatile boolean e = false;
    public final com.google.firebase.messaging.u f;

    public c(BlockingQueue blockingQueue, BlockingQueue blockingQueue2, b bVar, u uVar) {
        this.a = blockingQueue;
        this.b = blockingQueue2;
        this.c = bVar;
        this.d = uVar;
        com.google.firebase.messaging.u uVar2 = new com.google.firebase.messaging.u();
        uVar2.a = new HashMap();
        uVar2.b = uVar;
        uVar2.c = this;
        uVar2.d = blockingQueue2;
        this.f = uVar2;
    }

    private void a() throws InterruptedException {
        l lVar = (l) this.a.take();
        lVar.addMarker("cache-queue-take");
        lVar.sendEvent(1);
        try {
            if (lVar.isCanceled()) {
                lVar.finish("cache-discard-canceled");
                return;
            }
            a aVarA = ((com.android.volley.toolbox.d) this.c).a(lVar.getCacheKey());
            if (aVarA == null) {
                lVar.addMarker("cache-miss");
                if (!this.f.h(lVar)) {
                    this.b.put(lVar);
                }
                return;
            }
            long jCurrentTimeMillis = System.currentTimeMillis();
            if (aVarA.e < jCurrentTimeMillis) {
                lVar.addMarker("cache-hit-expired");
                lVar.setCacheEntry(aVarA);
                if (!this.f.h(lVar)) {
                    this.b.put(lVar);
                }
                return;
            }
            lVar.addMarker("cache-hit");
            t networkResponse = lVar.parseNetworkResponse(new h(aVarA.a, aVarA.g));
            lVar.addMarker("cache-hit-parsed");
            if (networkResponse.c == null) {
                if (aVarA.f < jCurrentTimeMillis) {
                    lVar.addMarker("cache-hit-refresh-needed");
                    lVar.setCacheEntry(aVarA);
                    networkResponse.d = true;
                    if (this.f.h(lVar)) {
                        ((com.airbnb.lottie.network.d) this.d).p(lVar, networkResponse, null);
                    } else {
                        ((com.airbnb.lottie.network.d) this.d).p(lVar, networkResponse, new com.google.common.util.concurrent.d(this, false, lVar, 10));
                    }
                } else {
                    ((com.airbnb.lottie.network.d) this.d).p(lVar, networkResponse, null);
                }
                return;
            }
            lVar.addMarker("cache-parsing-failed");
            b bVar = this.c;
            String cacheKey = lVar.getCacheKey();
            com.android.volley.toolbox.d dVar = (com.android.volley.toolbox.d) bVar;
            synchronized (dVar) {
                a aVarA2 = dVar.a(cacheKey);
                if (aVarA2 != null) {
                    aVarA2.f = 0L;
                    aVarA2.e = 0L;
                    dVar.f(cacheKey, aVarA2);
                }
            }
            lVar.setCacheEntry(null);
            if (!this.f.h(lVar)) {
                this.b.put(lVar);
            }
        } finally {
            lVar.sendEvent(2);
        }
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public final void run() throws SecurityException, IllegalArgumentException {
        if (g) {
            y.c("start new dispatcher", new Object[0]);
        }
        Process.setThreadPriority(10);
        ((com.android.volley.toolbox.d) this.c).d();
        while (true) {
            try {
                a();
            } catch (InterruptedException unused) {
                if (this.e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                y.b("Ignoring spurious interrupt of CacheDispatcher thread; use quit() to terminate it", new Object[0]);
            }
        }
    }
}
