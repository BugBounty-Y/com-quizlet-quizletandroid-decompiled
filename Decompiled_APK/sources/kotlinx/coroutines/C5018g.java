package kotlinx.coroutines;

import java.util.concurrent.locks.LockSupport;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.coroutines.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5018g extends AbstractC4972a {
    public final Thread d;
    public final Z e;

    public C5018g(CoroutineContext coroutineContext, Thread thread, Z z) {
        super(coroutineContext, true, true);
        this.d = thread;
        this.e = z;
    }

    @Override // kotlinx.coroutines.q0
    public final void u(Object obj) {
        Thread threadCurrentThread = Thread.currentThread();
        Thread thread = this.d;
        if (Intrinsics.b(threadCurrentThread, thread)) {
            return;
        }
        LockSupport.unpark(thread);
    }
}
