package com.android.billingclient.api;

import java.io.Serializable;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public final class p implements ThreadFactory {
    public final /* synthetic */ int a;
    public final Serializable b;
    public final Object c;

    public p() {
        this.a = 0;
        this.c = Executors.defaultThreadFactory();
        this.b = new AtomicInteger(1);
    }

    @Override // java.util.concurrent.ThreadFactory
    public final Thread newThread(Runnable runnable) {
        switch (this.a) {
            case 0:
                AtomicInteger atomicInteger = (AtomicInteger) this.b;
                Thread threadNewThread = ((ThreadFactory) this.c).newThread(runnable);
                threadNewThread.setName("PlayBillingLibrary-" + atomicInteger.getAndIncrement());
                return threadNewThread;
            case 1:
                return new Thread(runnable, "AdWorker(" + ((String) this.c) + ") #" + ((AtomicInteger) this.b).getAndIncrement());
            default:
                Thread threadNewThread2 = ((ThreadFactory) this.c).newThread(new androidx.camera.core.impl.utils.executor.j(runnable, 3));
                threadNewThread2.setName((String) this.b);
                return threadNewThread2;
        }
    }

    public p(String str, int i) {
        this.a = i;
        switch (i) {
            case 2:
                this.c = Executors.defaultThreadFactory();
                this.b = str;
                break;
            default:
                this.c = str;
                this.b = new AtomicInteger(1);
                break;
        }
    }
}
