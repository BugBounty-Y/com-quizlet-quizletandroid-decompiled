package com.android.volley;

import android.net.TrafficStats;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;
import java.util.concurrent.BlockingQueue;

/* loaded from: classes.dex */
public final class g extends Thread {
    public final BlockingQueue a;
    public final f b;
    public final b c;
    public final u d;
    public volatile boolean e = false;

    public g(BlockingQueue blockingQueue, f fVar, b bVar, u uVar) {
        this.a = blockingQueue;
        this.b = fVar;
        this.c = bVar;
        this.d = uVar;
    }

    private void a() throws InterruptedException {
        l lVar = (l) this.a.take();
        u uVar = this.d;
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        lVar.sendEvent(3);
        Object obj = null;
        try {
            try {
                lVar.addMarker("network-queue-take");
                if (lVar.isCanceled()) {
                    lVar.finish("network-discard-cancelled");
                    lVar.notifyListenerResponseNotUsable();
                    return;
                }
                TrafficStats.setThreadStatsTag(lVar.getTrafficStatsTag());
                h hVarQ = ((androidx.work.impl.model.l) this.b).q(lVar);
                lVar.addMarker("network-http-complete");
                if (hVarQ.e && lVar.hasHadResponseDelivered()) {
                    lVar.finish("not-modified");
                    lVar.notifyListenerResponseNotUsable();
                    return;
                }
                t networkResponse = lVar.parseNetworkResponse(hVarQ);
                lVar.addMarker("network-parse-complete");
                if (lVar.shouldCache() && networkResponse.b != null) {
                    ((com.android.volley.toolbox.d) this.c).f(lVar.getCacheKey(), networkResponse.b);
                    lVar.addMarker("network-cache-written");
                }
                lVar.markDelivered();
                ((com.airbnb.lottie.network.d) uVar).p(lVar, networkResponse, null);
                lVar.notifyListenerResponseReceived(networkResponse);
            } catch (VolleyError e) {
                e.b = SystemClock.elapsedRealtime() - jElapsedRealtime;
                VolleyError networkError = lVar.parseNetworkError(e);
                com.airbnb.lottie.network.d dVar = (com.airbnb.lottie.network.d) uVar;
                dVar.getClass();
                lVar.addMarker("post-error");
                ((androidx.core.provider.j) dVar.b).execute(new androidx.core.provider.k(lVar, new t(networkError), obj, 4));
                lVar.notifyListenerResponseNotUsable();
            } catch (Exception e2) {
                Log.e("Volley", y.a("Unhandled exception %s", e2.toString()), e2);
                VolleyError volleyError = new VolleyError(e2);
                volleyError.b = SystemClock.elapsedRealtime() - jElapsedRealtime;
                com.airbnb.lottie.network.d dVar2 = (com.airbnb.lottie.network.d) uVar;
                dVar2.getClass();
                lVar.addMarker("post-error");
                ((androidx.core.provider.j) dVar2.b).execute(new androidx.core.provider.k(lVar, new t(volleyError), obj, 4));
                lVar.notifyListenerResponseNotUsable();
            }
        } finally {
            lVar.sendEvent(4);
        }
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public final void run() throws SecurityException, IllegalArgumentException {
        Process.setThreadPriority(10);
        while (true) {
            try {
                a();
            } catch (InterruptedException unused) {
                if (this.e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                y.b("Ignoring spurious interrupt of NetworkDispatcher thread; use quit() to terminate it", new Object[0]);
            }
        }
    }
}
