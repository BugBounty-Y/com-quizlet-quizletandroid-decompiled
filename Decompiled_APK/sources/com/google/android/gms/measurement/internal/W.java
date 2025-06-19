package com.google.android.gms.measurement.internal;

import android.os.Process;
import java.util.AbstractQueue;
import java.util.concurrent.BlockingQueue;

/* loaded from: classes2.dex */
public final class W extends Thread {
    public final Object a;
    public final AbstractQueue b;
    public boolean c = false;
    public final /* synthetic */ X d;

    /* JADX WARN: Multi-variable type inference failed */
    public W(X x, String str, BlockingQueue blockingQueue) {
        this.d = x;
        com.google.android.gms.common.internal.u.h(blockingQueue);
        this.a = new Object();
        this.b = (AbstractQueue) blockingQueue;
        setName(str);
    }

    public final void a() {
        X x = this.d;
        synchronized (x.j) {
            try {
                if (!this.c) {
                    x.k.release();
                    x.j.notifyAll();
                    if (this == x.d) {
                        x.d = null;
                    } else if (this == x.e) {
                        x.e = null;
                    } else {
                        I i = ((Y) x.b).i;
                        Y.k(i);
                        i.g.f("Current scheduler thread is neither worker nor network");
                    }
                    this.c = true;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public final void run() throws InterruptedException {
        boolean z = false;
        while (!z) {
            try {
                this.d.k.acquire();
                z = true;
            } catch (InterruptedException e) {
                I i = ((Y) this.d.b).i;
                Y.k(i);
                i.j.g(String.valueOf(getName()).concat(" was interrupted"), e);
            }
        }
        try {
            int threadPriority = Process.getThreadPriority(Process.myTid());
            while (true) {
                AbstractQueue abstractQueue = this.b;
                V v = (V) abstractQueue.poll();
                if (v != null) {
                    Process.setThreadPriority(true != v.b ? 10 : threadPriority);
                    v.run();
                } else {
                    Object obj = this.a;
                    synchronized (obj) {
                        if (abstractQueue.peek() == null) {
                            this.d.getClass();
                            try {
                                obj.wait(30000L);
                            } catch (InterruptedException e2) {
                                I i2 = ((Y) this.d.b).i;
                                Y.k(i2);
                                i2.j.g(String.valueOf(getName()).concat(" was interrupted"), e2);
                            }
                        }
                    }
                    synchronized (this.d.j) {
                        if (this.b.peek() == null) {
                            a();
                            a();
                            return;
                        }
                    }
                }
            }
        } catch (Throwable th) {
            a();
            throw th;
        }
    }
}
