package kotlinx.coroutines.internal;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C0;
import kotlinx.coroutines.C5036u;
import kotlinx.coroutines.DispatchException;
import kotlinx.coroutines.E;
import kotlinx.coroutines.M;
import kotlinx.coroutines.Z;

/* loaded from: classes3.dex */
public final class f extends M implements kotlin.coroutines.jvm.internal.d, kotlin.coroutines.h {
    public static final /* synthetic */ AtomicReferenceFieldUpdater h = AtomicReferenceFieldUpdater.newUpdater(f.class, Object.class, "_reusableCancellableContinuation$volatile");
    private volatile /* synthetic */ Object _reusableCancellableContinuation$volatile;
    public final AbstractC5040y d;
    public final kotlin.coroutines.jvm.internal.c e;
    public Object f;
    public final Object g;

    public f(AbstractC5040y abstractC5040y, kotlin.coroutines.jvm.internal.c cVar) {
        super(-1);
        this.d = abstractC5040y;
        this.e = cVar;
        this.f = b.b;
        this.g = t.b(cVar.getContext());
    }

    @Override // kotlinx.coroutines.M
    public final kotlin.coroutines.h d() {
        return this;
    }

    @Override // kotlin.coroutines.jvm.internal.d
    public final kotlin.coroutines.jvm.internal.d getCallerFrame() {
        return this.e;
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return this.e.getContext();
    }

    @Override // kotlinx.coroutines.M
    public final Object h() {
        Object obj = this.f;
        this.f = b.b;
        return obj;
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) throws DispatchException {
        Throwable thA = kotlin.r.a(obj);
        Object c5036u = thA == null ? obj : new C5036u(thA, false);
        kotlin.coroutines.jvm.internal.c cVar = this.e;
        CoroutineContext context = cVar.getContext();
        AbstractC5040y abstractC5040y = this.d;
        if (b.i(abstractC5040y, context)) {
            this.f = c5036u;
            this.c = 0;
            b.h(abstractC5040y, cVar.getContext(), this);
            return;
        }
        Z zA = C0.a();
        if (zA.b >= 4294967296L) {
            this.f = c5036u;
            this.c = 0;
            zA.l0(this);
            return;
        }
        zA.n0(true);
        try {
            CoroutineContext context2 = cVar.getContext();
            Object objC = t.c(context2, this.g);
            try {
                cVar.resumeWith(obj);
                Unit unit = Unit.a;
                while (zA.p0()) {
                }
            } finally {
                t.a(context2, objC);
            }
        } finally {
            try {
            } finally {
            }
        }
    }

    public final String toString() {
        return "DispatchedContinuation[" + this.d + ", " + E.G(this.e) + ']';
    }
}
