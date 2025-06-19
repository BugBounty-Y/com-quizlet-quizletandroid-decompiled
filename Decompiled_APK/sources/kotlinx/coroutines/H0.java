package kotlinx.coroutines;

import kotlin.Pair;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;

/* loaded from: classes3.dex */
public final class H0 extends kotlinx.coroutines.internal.p {
    public final ThreadLocal e;
    private volatile boolean threadLocalIsSet;

    /* JADX WARN: Illegal instructions before constructor call */
    public H0(kotlin.coroutines.h hVar, CoroutineContext coroutineContext) {
        I0 i0 = I0.a;
        super(hVar, coroutineContext.get(i0) == null ? coroutineContext.plus(i0) : coroutineContext);
        this.e = new ThreadLocal();
        if (hVar.getContext().get(kotlin.coroutines.j.a1) instanceof AbstractC5040y) {
            return;
        }
        Object objC = kotlinx.coroutines.internal.t.c(coroutineContext, null);
        kotlinx.coroutines.internal.t.a(coroutineContext, objC);
        q0(coroutineContext, objC);
    }

    @Override // kotlinx.coroutines.internal.p
    public final void n0() {
        p0();
    }

    public final boolean o0() {
        boolean z = this.threadLocalIsSet && this.e.get() == null;
        this.e.remove();
        return !z;
    }

    public final void p0() {
        if (this.threadLocalIsSet) {
            Pair pair = (Pair) this.e.get();
            if (pair != null) {
                kotlinx.coroutines.internal.t.a((CoroutineContext) pair.a, pair.b);
            }
            this.e.remove();
        }
    }

    public final void q0(CoroutineContext coroutineContext, Object obj) {
        this.threadLocalIsSet = true;
        this.e.set(new Pair(coroutineContext, obj));
    }

    @Override // kotlinx.coroutines.internal.p, kotlinx.coroutines.q0
    public final void v(Object obj) {
        p0();
        Object objB = E.B(obj);
        kotlin.coroutines.h hVar = this.d;
        CoroutineContext context = hVar.getContext();
        Object objC = kotlinx.coroutines.internal.t.c(context, null);
        H0 h0C = objC != kotlinx.coroutines.internal.t.a ? AbstractC5038w.c(hVar, context, objC) : null;
        try {
            hVar.resumeWith(objB);
            Unit unit = Unit.a;
            if (h0C == null || h0C.o0()) {
                kotlinx.coroutines.internal.t.a(context, objC);
            }
        } catch (Throwable th) {
            if (h0C == null || h0C.o0()) {
                kotlinx.coroutines.internal.t.a(context, objC);
            }
            throw th;
        }
    }
}
