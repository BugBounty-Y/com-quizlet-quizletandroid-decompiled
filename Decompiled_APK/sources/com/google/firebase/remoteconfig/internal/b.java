package com.google.firebase.remoteconfig.internal;

import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.m;
import java.util.HashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/* loaded from: classes2.dex */
public final class b {
    public static final HashMap d = new HashMap();
    public static final androidx.arch.core.executor.a e = new androidx.arch.core.executor.a(1);
    public final Executor a;
    public final k b;
    public m c = null;

    public b(Executor executor, k kVar) {
        this.a = executor;
        this.b = kVar;
    }

    public static Object a(Task task) throws ExecutionException, TimeoutException {
        TimeUnit timeUnit = TimeUnit.SECONDS;
        com.google.android.material.floatingactionbutton.c cVar = new com.google.android.material.floatingactionbutton.c();
        Executor executor = e;
        task.d(executor, cVar);
        task.c(executor, cVar);
        task.a(executor, cVar);
        if (!((CountDownLatch) cVar.b).await(5L, timeUnit)) {
            throw new TimeoutException("Task await timed out.");
        }
        if (task.l()) {
            return task.h();
        }
        throw new ExecutionException(task.g());
    }

    public final synchronized Task b() {
        try {
            m mVar = this.c;
            if (mVar == null || (mVar.k() && !this.c.l())) {
                this.c = S3.g(this.a, new androidx.work.impl.utils.d(this.b, 7));
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.c;
    }

    public final c c() {
        synchronized (this) {
            try {
                m mVar = this.c;
                if (mVar != null && mVar.l()) {
                    return (c) this.c.h();
                }
                try {
                    Task taskB = b();
                    TimeUnit timeUnit = TimeUnit.SECONDS;
                    return (c) a(taskB);
                } catch (InterruptedException | ExecutionException | TimeoutException unused) {
                    return null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
