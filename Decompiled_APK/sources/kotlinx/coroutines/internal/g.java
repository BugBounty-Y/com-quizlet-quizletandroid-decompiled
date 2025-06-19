package kotlinx.coroutines.internal;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.G;
import kotlinx.coroutines.J;
import kotlinx.coroutines.Q;

/* loaded from: classes3.dex */
public final class g extends AbstractC5040y implements J {
    public static final /* synthetic */ AtomicIntegerFieldUpdater g = AtomicIntegerFieldUpdater.newUpdater(g.class, "runningWorkers$volatile");
    public final /* synthetic */ J b;
    public final AbstractC5040y c;
    public final int d;
    public final j e;
    public final Object f;
    private volatile /* synthetic */ int runningWorkers$volatile;

    /* JADX WARN: Multi-variable type inference failed */
    public g(AbstractC5040y abstractC5040y, int i) {
        J j = abstractC5040y instanceof J ? (J) abstractC5040y : null;
        this.b = j == null ? G.a : j;
        this.c = abstractC5040y;
        this.d = i;
        this.e = new j();
        this.f = new Object();
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void B(CoroutineContext coroutineContext, Runnable runnable) {
        Runnable runnableK0;
        this.e.a(runnable);
        AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = g;
        if (atomicIntegerFieldUpdater.get(this) >= this.d || !l0() || (runnableK0 = k0()) == null) {
            return;
        }
        try {
            this.c.B(this, new com.google.android.gms.tasks.k(8, this, runnableK0));
        } catch (Throwable th) {
            atomicIntegerFieldUpdater.decrementAndGet(this);
            throw th;
        }
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final AbstractC5040y c0(int i) {
        b.a(i);
        return i >= this.d ? this : super.c0(i);
    }

    @Override // kotlinx.coroutines.J
    public final void f(long j, C5028l c5028l) {
        this.b.f(j, c5028l);
    }

    @Override // kotlinx.coroutines.J
    public final Q i(long j, Runnable runnable, CoroutineContext coroutineContext) {
        return this.b.i(j, runnable, coroutineContext);
    }

    public final Runnable k0() {
        while (true) {
            Runnable runnable = (Runnable) this.e.d();
            if (runnable != null) {
                return runnable;
            }
            synchronized (this.f) {
                AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = g;
                atomicIntegerFieldUpdater.decrementAndGet(this);
                if (this.e.c() == 0) {
                    return null;
                }
                atomicIntegerFieldUpdater.incrementAndGet(this);
            }
        }
    }

    public final boolean l0() {
        synchronized (this.f) {
            AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = g;
            if (atomicIntegerFieldUpdater.get(this) >= this.d) {
                return false;
            }
            atomicIntegerFieldUpdater.incrementAndGet(this);
            return true;
        }
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext coroutineContext, Runnable runnable) {
        Runnable runnableK0;
        this.e.a(runnable);
        AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = g;
        if (atomicIntegerFieldUpdater.get(this) >= this.d || !l0() || (runnableK0 = k0()) == null) {
            return;
        }
        try {
            b.h(this.c, this, new com.google.android.gms.tasks.k(8, this, runnableK0));
        } catch (Throwable th) {
            atomicIntegerFieldUpdater.decrementAndGet(this);
            throw th;
        }
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.c);
        sb.append(".limitedParallelism(");
        return android.support.v4.media.session.a.q(sb, this.d, ')');
    }
}
