package androidx.camera.core.impl.utils.executor;

import androidx.appcompat.app.J;
import java.util.ArrayDeque;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/* loaded from: classes.dex */
public final class k implements Executor {
    public final Executor b;
    public final ArrayDeque a = new ArrayDeque();
    public final J c = new J(this, 4);
    public int d = 1;
    public long e = 0;

    public k(Executor executor) {
        executor.getClass();
        this.b = executor;
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        runnable.getClass();
        synchronized (this.a) {
            int i = this.d;
            if (i != 4 && i != 3) {
                long j = this.e;
                j jVar = new j(runnable, 0);
                this.a.add(jVar);
                this.d = 2;
                try {
                    this.b.execute(this.c);
                    if (this.d != 2) {
                        return;
                    }
                    synchronized (this.a) {
                        try {
                            if (this.e == j && this.d == 2) {
                                this.d = 3;
                            }
                        } finally {
                        }
                    }
                    return;
                } catch (Error | RuntimeException e) {
                    synchronized (this.a) {
                        try {
                            int i2 = this.d;
                            boolean z = true;
                            if ((i2 != 1 && i2 != 2) || !this.a.removeLastOccurrence(jVar)) {
                                z = false;
                            }
                            if (!(e instanceof RejectedExecutionException) || z) {
                                throw e;
                            }
                        } finally {
                        }
                    }
                    return;
                }
            }
            this.a.add(runnable);
        }
    }
}
