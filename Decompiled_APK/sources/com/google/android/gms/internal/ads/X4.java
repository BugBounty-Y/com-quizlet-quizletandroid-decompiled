package com.google.android.gms.internal.ads;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public final class X4 implements ThreadFactory {
    public final /* synthetic */ int a;
    public final AtomicInteger b;
    public final Object c;

    public X4() {
        this.a = 0;
        this.c = Executors.defaultThreadFactory();
        this.b = new AtomicInteger(1);
    }

    @Override // java.util.concurrent.ThreadFactory
    public final Thread newThread(Runnable runnable) {
        switch (this.a) {
            case 0:
                AtomicInteger atomicInteger = this.b;
                Thread threadNewThread = ((ThreadFactory) this.c).newThread(runnable);
                threadNewThread.setName("gads-" + atomicInteger.getAndIncrement());
                return threadNewThread;
            default:
                return new Thread(runnable, "AdWorker(" + ((String) this.c) + ") #" + this.b.getAndIncrement());
        }
    }

    public X4(String str) {
        this.a = 1;
        this.c = str;
        this.b = new AtomicInteger(1);
    }
}
