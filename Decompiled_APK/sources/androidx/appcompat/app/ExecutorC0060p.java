package androidx.appcompat.app;

import java.util.ArrayDeque;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.appcompat.app.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class ExecutorC0060p implements Executor {
    public final /* synthetic */ int a;
    public final Object b;
    public Object c;
    public final Object d;
    public final Object e;

    public /* synthetic */ ExecutorC0060p(Executor executor, Q q, com.google.firebase.platforminfo.c cVar, com.google.android.gms.tasks.f fVar) {
        this.a = 3;
        this.d = executor;
        this.b = q;
        this.e = cVar;
        this.c = fVar;
    }

    public void a() {
        switch (this.a) {
            case 0:
                synchronized (this.d) {
                    try {
                        Runnable runnable = (Runnable) ((ArrayDeque) this.b).poll();
                        this.c = runnable;
                        if (runnable != null) {
                            ((androidx.camera.core.impl.utils.executor.a) this.e).execute(runnable);
                        }
                    } finally {
                    }
                }
                return;
            case 1:
                synchronized (this.d) {
                    try {
                        Object objPoll = ((ArrayDeque) this.b).poll();
                        Runnable runnable2 = (Runnable) objPoll;
                        this.c = runnable2;
                        if (objPoll != null) {
                            ((Executor) this.e).execute(runnable2);
                        }
                        Unit unit = Unit.a;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
            default:
                Runnable runnable3 = (Runnable) ((ArrayDeque) this.b).poll();
                this.c = runnable3;
                if (runnable3 != null) {
                    ((ExecutorService) this.e).execute(runnable3);
                    return;
                }
                return;
        }
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable command) {
        switch (this.a) {
            case 0:
                synchronized (this.d) {
                    try {
                        ((ArrayDeque) this.b).add(new androidx.activity.r(1, this, command));
                        if (((Runnable) this.c) == null) {
                            a();
                        }
                    } finally {
                    }
                }
                return;
            case 1:
                Intrinsics.checkNotNullParameter(command, "command");
                synchronized (this.d) {
                    try {
                        ((ArrayDeque) this.b).offer(new androidx.credentials.playservices.controllers.c(5, command, this));
                        if (((Runnable) this.c) == null) {
                            a();
                        }
                        Unit unit = Unit.a;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
            case 2:
                synchronized (this.d) {
                    try {
                        ((ArrayDeque) this.b).add(new com.google.common.util.concurrent.d(7, this, command));
                        if (((Runnable) this.c) == null) {
                            a();
                        }
                    } finally {
                    }
                }
                return;
            default:
                try {
                    ((Executor) this.d).execute(command);
                    return;
                } catch (RuntimeException e) {
                    if (((com.google.android.gms.tasks.m) ((Q) this.b).a).k()) {
                        ((com.google.firebase.platforminfo.c) this.e).j();
                    } else {
                        ((com.google.android.gms.tasks.f) this.c).a(e);
                    }
                    throw e;
                }
        }
    }

    public ExecutorC0060p(Executor executor) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(executor, "executor");
        this.e = executor;
        this.b = new ArrayDeque();
        this.d = new Object();
    }

    public ExecutorC0060p(ExecutorService executorService) {
        this.a = 2;
        this.e = executorService;
        this.b = new ArrayDeque();
        this.d = new Object();
    }

    public ExecutorC0060p(androidx.camera.core.impl.utils.executor.a aVar) {
        this.a = 0;
        this.d = new Object();
        this.b = new ArrayDeque();
        this.e = aVar;
    }
}
