package androidx.compose.foundation;

import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class y0 {
    public final AtomicReference a = new AtomicReference(null);
    public final kotlinx.coroutines.sync.c b = kotlinx.coroutines.sync.d.a();

    public static final void a(y0 y0Var, v0 v0Var) {
        while (true) {
            AtomicReference atomicReference = y0Var.a;
            v0 v0Var2 = (v0) atomicReference.get();
            if (v0Var2 != null && v0Var.a.compareTo(v0Var2.a) < 0) {
                throw new CancellationException("Current mutation had a higher priority");
            }
            while (!atomicReference.compareAndSet(v0Var2, v0Var)) {
                if (atomicReference.get() != v0Var2) {
                    break;
                }
            }
            if (v0Var2 != null) {
                v0Var2.b.j(new MutationInterruptedException());
                return;
            }
            return;
        }
    }
}
