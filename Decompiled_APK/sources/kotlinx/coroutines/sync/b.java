package kotlinx.coroutines.sync;

import com.android.billingclient.api.C1472a;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.DispatchException;
import kotlinx.coroutines.InterfaceC5026k;
import kotlinx.coroutines.J0;
import kotlinx.coroutines.internal.q;

/* loaded from: classes3.dex */
public final class b implements InterfaceC5026k, J0 {
    public final C5028l a;
    public final /* synthetic */ c b;

    public b(c cVar, C5028l c5028l) {
        this.b = cVar;
        this.a = c5028l;
    }

    @Override // kotlinx.coroutines.J0
    public final void a(q qVar, int i) {
        this.a.a(qVar, i);
    }

    @Override // kotlinx.coroutines.InterfaceC5026k
    public final boolean b(Throwable th) {
        return this.a.b(th);
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return this.a.e;
    }

    @Override // kotlinx.coroutines.InterfaceC5026k
    public final C1472a k(Object obj, kotlin.jvm.functions.c cVar) {
        c cVar2 = this.b;
        androidx.navigation.serialization.j jVar = new androidx.navigation.serialization.j(4, cVar2, this);
        C1472a c1472aG = this.a.G((Unit) obj, jVar);
        if (c1472aG != null) {
            c.h.set(cVar2, null);
        }
        return c1472aG;
    }

    @Override // kotlinx.coroutines.InterfaceC5026k
    public final void m(Object obj, kotlin.jvm.functions.c cVar) throws DispatchException {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = c.h;
        c cVar2 = this.b;
        atomicReferenceFieldUpdater.set(cVar2, null);
        com.quizlet.quizletandroid.ui.subject.f fVar = new com.quizlet.quizletandroid.ui.subject.f(11, cVar2, this);
        C5028l c5028l = this.a;
        c5028l.D((Unit) obj, c5028l.c, new androidx.navigation.serialization.i(fVar, 7));
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) {
        this.a.resumeWith(obj);
    }

    @Override // kotlinx.coroutines.InterfaceC5026k
    public final void t(Object obj) throws DispatchException {
        this.a.t(obj);
    }
}
