package kotlinx.coroutines.channels;

import java.util.concurrent.CancellationException;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.AbstractC4972a;
import kotlinx.coroutines.E;
import kotlinx.coroutines.JobCancellationException;

/* loaded from: classes3.dex */
public final class t extends AbstractC4972a implements u, l {
    public final h d;

    public t(CoroutineContext coroutineContext, h hVar, boolean z, boolean z2) {
        super(coroutineContext, z, z2);
        this.d = hVar;
    }

    @Override // kotlinx.coroutines.channels.w
    public final Object c(kotlin.coroutines.jvm.internal.c cVar) {
        return this.d.c(cVar);
    }

    @Override // kotlinx.coroutines.channels.w
    public final com.quizlet.login.common.interactors.d e() {
        return this.d.e();
    }

    @Override // kotlinx.coroutines.channels.w
    public final Object g(kotlin.coroutines.jvm.internal.i iVar) {
        h hVar = this.d;
        hVar.getClass();
        Object objE = h.E(hVar, iVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        return objE;
    }

    @Override // kotlinx.coroutines.channels.w
    public final Object h() {
        return this.d.h();
    }

    @Override // kotlinx.coroutines.channels.w
    public final c iterator() {
        h hVar = this.d;
        hVar.getClass();
        return new c(hVar);
    }

    @Override // kotlinx.coroutines.q0, kotlinx.coroutines.InterfaceC5025j0, kotlinx.coroutines.channels.w
    public final void j(CancellationException cancellationException) {
        if (isCancelled()) {
            return;
        }
        if (cancellationException == null) {
            cancellationException = new JobCancellationException(B(), null, this);
        }
        z(cancellationException);
    }

    @Override // kotlinx.coroutines.AbstractC4972a
    public final void k0(Throwable th, boolean z) {
        if (this.d.k(th, false) || z) {
            return;
        }
        E.u(this.c, th);
    }

    @Override // kotlinx.coroutines.AbstractC4972a
    public final void l0(Object obj) {
        this.d.i(null);
    }

    @Override // kotlinx.coroutines.channels.x
    public final void n(Function1 function1) {
        this.d.n(function1);
    }

    public boolean n0(Throwable th) {
        return this.d.k(th, false);
    }

    @Override // kotlinx.coroutines.channels.x
    public Object o(Object obj) {
        return this.d.o(obj);
    }

    @Override // kotlinx.coroutines.channels.x
    public Object s(Object obj, kotlin.coroutines.h hVar) {
        return this.d.s(obj, hVar);
    }

    @Override // kotlinx.coroutines.q0
    public final void z(CancellationException cancellationException) {
        this.d.k(cancellationException, true);
        x(cancellationException);
    }
}
