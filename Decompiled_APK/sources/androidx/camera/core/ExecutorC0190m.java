package androidx.camera.core;

import androidx.camera.camera2.internal.C0138o;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* renamed from: androidx.camera.core.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class ExecutorC0190m implements Executor {
    public static final androidx.arch.core.executor.c c = new androidx.arch.core.executor.c(1);
    public final Object a = new Object();
    public ThreadPoolExecutor b;

    public ExecutorC0190m() {
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue(), c);
        threadPoolExecutor.setRejectedExecutionHandler(new RejectedExecutionHandlerC0189l(0));
        this.b = threadPoolExecutor;
    }

    public final void a(C0138o c0138o) {
        ThreadPoolExecutor threadPoolExecutor;
        c0138o.getClass();
        synchronized (this.a) {
            try {
                if (this.b.isShutdown()) {
                    ThreadPoolExecutor threadPoolExecutor2 = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue(), c);
                    threadPoolExecutor2.setRejectedExecutionHandler(new RejectedExecutionHandlerC0189l(0));
                    this.b = threadPoolExecutor2;
                }
                threadPoolExecutor = this.b;
            } catch (Throwable th) {
                throw th;
            }
        }
        int iMax = Math.max(1, new LinkedHashSet((ArrayList) c0138o.g).size());
        threadPoolExecutor.setMaximumPoolSize(iMax);
        threadPoolExecutor.setCorePoolSize(iMax);
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        runnable.getClass();
        synchronized (this.a) {
            this.b.execute(runnable);
        }
    }
}
