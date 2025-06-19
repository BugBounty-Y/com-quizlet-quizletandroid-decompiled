package kotlinx.coroutines.scheduling;

import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class l extends AbstractC5040y {
    public static final l b = new l();

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void B(CoroutineContext coroutineContext, Runnable runnable) {
        e.c.b.d(runnable, true, true);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final AbstractC5040y c0(int i) {
        kotlinx.coroutines.internal.b.a(i);
        return i >= k.d ? this : super.c0(i);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext coroutineContext, Runnable runnable) {
        e.c.b.d(runnable, true, false);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final String toString() {
        return "Dispatchers.IO";
    }
}
