package com.android.volley;

import android.os.Handler;
import android.os.Looper;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public abstract class q {
    private static final int DEFAULT_NETWORK_THREAD_POOL_SIZE = 4;
    private final b mCache;
    private c mCacheDispatcher;
    private final PriorityBlockingQueue<l> mCacheQueue;
    private final Set<l> mCurrentRequests;
    private final u mDelivery;
    private final g[] mDispatchers;
    private final List<n> mEventListeners;
    private final List<p> mFinishedListeners;
    private final f mNetwork;
    private final PriorityBlockingQueue<l> mNetworkQueue;
    private final AtomicInteger mSequenceGenerator;

    public q(b bVar, f fVar) {
        com.airbnb.lottie.network.d dVar = new com.airbnb.lottie.network.d(new Handler(Looper.getMainLooper()));
        this.mSequenceGenerator = new AtomicInteger();
        this.mCurrentRequests = new HashSet();
        this.mCacheQueue = new PriorityBlockingQueue<>();
        this.mNetworkQueue = new PriorityBlockingQueue<>();
        this.mFinishedListeners = new ArrayList();
        this.mEventListeners = new ArrayList();
        this.mCache = bVar;
        this.mNetwork = fVar;
        this.mDispatchers = new g[4];
        this.mDelivery = dVar;
    }

    public <T> l add(l lVar) {
        lVar.setRequestQueue(this);
        synchronized (this.mCurrentRequests) {
            this.mCurrentRequests.add(lVar);
        }
        lVar.setSequence(getSequenceNumber());
        lVar.addMarker("add-to-queue");
        sendRequestEvent(lVar, 0);
        beginRequest(lVar);
        return lVar;
    }

    public void addRequestEventListener(n nVar) {
        synchronized (this.mEventListeners) {
            this.mEventListeners.add(nVar);
        }
    }

    @Deprecated
    public <T> void addRequestFinishedListener(p pVar) {
        synchronized (this.mFinishedListeners) {
            this.mFinishedListeners.add(pVar);
        }
    }

    public <T> void beginRequest(l lVar) {
        if (lVar.shouldCache()) {
            this.mCacheQueue.add(lVar);
        } else {
            sendRequestOverNetwork(lVar);
        }
    }

    public void cancelAll(o oVar) {
        synchronized (this.mCurrentRequests) {
            try {
                for (l lVar : this.mCurrentRequests) {
                    if (oVar.apply(lVar)) {
                        lVar.cancel();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public <T> void finish(l lVar) {
        synchronized (this.mCurrentRequests) {
            this.mCurrentRequests.remove(lVar);
        }
        synchronized (this.mFinishedListeners) {
            Iterator<p> it2 = this.mFinishedListeners.iterator();
            if (it2.hasNext()) {
                if (it2.next() != null) {
                    throw new ClassCastException();
                }
                throw null;
            }
        }
        sendRequestEvent(lVar, 5);
    }

    public b getCache() {
        return this.mCache;
    }

    public u getResponseDelivery() {
        return this.mDelivery;
    }

    public int getSequenceNumber() {
        return this.mSequenceGenerator.incrementAndGet();
    }

    public void removeRequestEventListener(n nVar) {
        synchronized (this.mEventListeners) {
            this.mEventListeners.remove(nVar);
        }
    }

    @Deprecated
    public <T> void removeRequestFinishedListener(p pVar) {
        synchronized (this.mFinishedListeners) {
            this.mFinishedListeners.remove(pVar);
        }
    }

    public void sendRequestEvent(l lVar, int i) {
        synchronized (this.mEventListeners) {
            try {
                Iterator<n> it2 = this.mEventListeners.iterator();
                if (it2.hasNext()) {
                    if (it2.next() != null) {
                        throw new ClassCastException();
                    }
                    throw null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public <T> void sendRequestOverNetwork(l lVar) {
        this.mNetworkQueue.add(lVar);
    }

    public void start() {
        stop();
        c cVar = new c(this.mCacheQueue, this.mNetworkQueue, this.mCache, this.mDelivery);
        this.mCacheDispatcher = cVar;
        cVar.start();
        for (int i = 0; i < this.mDispatchers.length; i++) {
            g gVar = new g(this.mNetworkQueue, this.mNetwork, this.mCache, this.mDelivery);
            this.mDispatchers[i] = gVar;
            gVar.start();
        }
    }

    public void stop() {
        c cVar = this.mCacheDispatcher;
        if (cVar != null) {
            cVar.e = true;
            cVar.interrupt();
        }
        for (g gVar : this.mDispatchers) {
            if (gVar != null) {
                gVar.e = true;
                gVar.interrupt();
            }
        }
    }

    public void cancelAll(Object obj) {
        if (obj != null) {
            cancelAll((o) new m(obj));
            return;
        }
        throw new IllegalArgumentException("Cannot cancelAll with a null tag");
    }
}
