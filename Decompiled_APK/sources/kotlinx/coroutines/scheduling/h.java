package kotlinx.coroutines.scheduling;

import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.AbstractC4973a0;

/* loaded from: classes3.dex */
public abstract class h extends AbstractC4973a0 {
    public c b;

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void B(CoroutineContext coroutineContext, Runnable runnable) {
        c.f(this.b, runnable, 2);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext coroutineContext, Runnable runnable) {
        c.f(this.b, runnable, 6);
    }
}
