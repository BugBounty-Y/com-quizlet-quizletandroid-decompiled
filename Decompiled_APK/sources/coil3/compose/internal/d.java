package coil3.compose.internal;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.O;

/* loaded from: classes.dex */
public final class d extends AbstractC5040y {
    public static final /* synthetic */ AtomicIntegerFieldUpdater d = AtomicIntegerFieldUpdater.newUpdater(d.class, "c");
    public final AbstractC5040y b;
    public volatile /* synthetic */ int c = 1;

    public d(AbstractC5040y abstractC5040y) {
        this.b = abstractC5040y;
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void B(CoroutineContext coroutineContext, Runnable runnable) {
        k0().B(coroutineContext, runnable);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final boolean a0(CoroutineContext coroutineContext) {
        return k0().a0(coroutineContext);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final AbstractC5040y c0(int i) {
        return k0().c0(i);
    }

    public final AbstractC5040y k0() {
        return d.get(this) == 1 ? O.b : this.b;
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext coroutineContext, Runnable runnable) {
        k0().r(coroutineContext, runnable);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final String toString() {
        return "DeferredDispatchCoroutineDispatcher(delegate=" + this.b + ')';
    }
}
