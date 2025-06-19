package kotlinx.coroutines.scheduling;

import java.util.concurrent.Executor;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.n;
import kotlinx.coroutines.AbstractC4973a0;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.internal.s;

/* loaded from: classes3.dex */
public final class d extends AbstractC4973a0 implements Executor {
    public static final d b = new d();
    public static final AbstractC5040y c;

    static {
        l lVar = l.b;
        int i = s.a;
        if (64 >= i) {
            i = 64;
        }
        c = lVar.c0(kotlinx.coroutines.internal.b.k(i, 12, "kotlinx.coroutines.io.parallelism"));
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void B(CoroutineContext coroutineContext, Runnable runnable) {
        c.B(coroutineContext, runnable);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final AbstractC5040y c0(int i) {
        return l.b.c0(i);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        throw new IllegalStateException("Cannot be invoked on Dispatchers.IO");
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        r(n.a, runnable);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext coroutineContext, Runnable runnable) {
        c.r(coroutineContext, runnable);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final String toString() {
        return "Dispatchers.IO";
    }
}
