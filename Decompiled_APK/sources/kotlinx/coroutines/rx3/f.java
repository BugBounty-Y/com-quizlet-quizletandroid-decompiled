package kotlinx.coroutines.rx3;

import io.reactivex.rxjava3.core.l;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlinx.coroutines.E;
import kotlinx.coroutines.channels.n;
import kotlinx.coroutines.channels.o;
import kotlinx.coroutines.channels.q;
import kotlinx.coroutines.channels.t;
import kotlinx.coroutines.channels.u;

/* loaded from: classes3.dex */
public final class f implements l {
    public final /* synthetic */ u a;
    public final /* synthetic */ AtomicReference b;

    public f(AtomicReference atomicReference, u uVar) {
        this.a = uVar;
        this.b = atomicReference;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        AtomicReference atomicReference;
        do {
            atomicReference = this.b;
            if (atomicReference.compareAndSet(null, bVar)) {
                return;
            }
        } while (atomicReference.get() == null);
        bVar.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        try {
            u uVar = this.a;
            Object objO = uVar.o(obj);
            if (objO instanceof n) {
                Object obj2 = ((o) E.D(kotlin.coroutines.n.a, new q(uVar, obj, null))).a;
            } else {
                Unit unit = Unit.a;
            }
        } catch (InterruptedException unused) {
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        ((t) this.a).n0(null);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        ((t) this.a).n0(th);
    }
}
