package androidx.compose.material;

import androidx.compose.foundation.u0;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.a j;
    public Object k;
    public F l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ u0 o;
    public final /* synthetic */ F p;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public E(u0 u0Var, F f, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = u0Var;
        this.p = f;
        this.q = (kotlin.coroutines.jvm.internal.i) function1;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        E e = new E(this.o, this.p, this.q, hVar);
        e.n = obj;
        return e;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r4v10 */
    /* JADX WARN: Type inference failed for: r4v2 */
    /* JADX WARN: Type inference failed for: r4v3, types: [kotlin.jvm.functions.Function1] */
    /* JADX WARN: Type inference failed for: r5v6, types: [kotlinx.coroutines.sync.a] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        F f;
        ?? r4;
        D d;
        kotlinx.coroutines.sync.c cVar;
        kotlinx.coroutines.sync.a aVar;
        F f2;
        Throwable th;
        D d2;
        AtomicReference atomicReference;
        AtomicReference atomicReference2;
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        ?? r1 = this.m;
        try {
            try {
                if (r1 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    CoroutineContext.Element element = ((kotlinx.coroutines.C) this.n).getCoroutineContext().get(C5023i0.a);
                    Intrinsics.d(element);
                    D d3 = new D(this.o, (InterfaceC5025j0) element);
                    while (true) {
                        f = this.p;
                        AtomicReference atomicReference3 = f.a;
                        D d4 = (D) atomicReference3.get();
                        if (d4 != null && d3.a.compareTo(d4.a) < 0) {
                            throw new CancellationException("Current mutation had a higher priority");
                        }
                        while (!atomicReference3.compareAndSet(d4, d3)) {
                            if (atomicReference3.get() != d4) {
                                break;
                            }
                        }
                        if (d4 != null) {
                            d4.b.j(null);
                        }
                        this.n = d3;
                        kotlinx.coroutines.sync.c cVar2 = f.b;
                        this.j = cVar2;
                        kotlin.coroutines.jvm.internal.i iVar = this.q;
                        this.k = iVar;
                        this.l = f;
                        this.m = 1;
                        if (cVar2.d(this) != aVar2) {
                            r4 = iVar;
                            d = d3;
                            cVar = cVar2;
                        }
                    }
                    return aVar2;
                }
                if (r1 != 1) {
                    if (r1 != 2) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    f2 = (F) this.k;
                    aVar = this.j;
                    d2 = (D) this.n;
                    try {
                        androidx.glance.appwidget.protobuf.Z.e(obj);
                        atomicReference2 = f2.a;
                        while (!atomicReference2.compareAndSet(d2, null) && atomicReference2.get() == d2) {
                        }
                        ((kotlinx.coroutines.sync.c) aVar).f(null);
                        return obj;
                    } catch (Throwable th2) {
                        th = th2;
                        atomicReference = f2.a;
                        while (!atomicReference.compareAndSet(d2, null)) {
                        }
                        throw th;
                    }
                }
                F f3 = this.l;
                Function1 function1 = (Function1) this.k;
                ?? r5 = this.j;
                d = (D) this.n;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                f = f3;
                r4 = function1;
                cVar = r5;
                this.n = d;
                this.j = aVar;
                this.k = f;
                this.l = null;
                this.m = 2;
                Object objInvoke = r4.invoke(this);
                if (objInvoke != aVar2) {
                    f2 = f;
                    obj = objInvoke;
                    d2 = d;
                    atomicReference2 = f2.a;
                    while (!atomicReference2.compareAndSet(d2, null)) {
                    }
                    ((kotlinx.coroutines.sync.c) aVar).f(null);
                    return obj;
                }
                return aVar2;
            } catch (Throwable th3) {
                f2 = f;
                th = th3;
                d2 = d;
                atomicReference = f2.a;
                while (!atomicReference.compareAndSet(d2, null) && atomicReference.get() == d2) {
                }
                throw th;
            }
            aVar = cVar;
        } catch (Throwable th4) {
            ((kotlinx.coroutines.sync.c) r1).f(null);
            throw th4;
        }
    }
}
