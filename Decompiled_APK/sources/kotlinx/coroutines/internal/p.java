package kotlinx.coroutines.internal;

import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.AbstractC4972a;
import kotlinx.coroutines.DispatchException;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public class p extends AbstractC4972a implements kotlin.coroutines.jvm.internal.d {
    public final kotlin.coroutines.h d;

    public p(kotlin.coroutines.h hVar, CoroutineContext coroutineContext) {
        super(coroutineContext, true, true);
        this.d = hVar;
    }

    @Override // kotlinx.coroutines.q0
    public final boolean T() {
        return true;
    }

    @Override // kotlin.coroutines.jvm.internal.d
    public final kotlin.coroutines.jvm.internal.d getCallerFrame() {
        kotlin.coroutines.h hVar = this.d;
        if (hVar instanceof kotlin.coroutines.jvm.internal.d) {
            return (kotlin.coroutines.jvm.internal.d) hVar;
        }
        return null;
    }

    public void n0() {
    }

    @Override // kotlinx.coroutines.q0
    public void u(Object obj) throws DispatchException {
        b.g(E.B(obj), kotlin.coroutines.intrinsics.h.b(this.d));
    }

    @Override // kotlinx.coroutines.q0
    public void v(Object obj) {
        this.d.resumeWith(E.B(obj));
    }
}
