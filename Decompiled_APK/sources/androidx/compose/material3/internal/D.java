package androidx.compose.material3.internal;

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
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.a j;
    public Object k;
    public E l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ u0 o;
    public final /* synthetic */ E p;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public D(u0 u0Var, E e, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = u0Var;
        this.p = e;
        this.q = (kotlin.coroutines.jvm.internal.i) function1;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        D d = new D(this.o, this.p, this.q, hVar);
        d.n = obj;
        return d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r4v10 */
    /* JADX WARN: Type inference failed for: r4v2 */
    /* JADX WARN: Type inference failed for: r4v3, types: [kotlin.jvm.functions.Function1] */
    /* JADX WARN: Type inference failed for: r5v6, types: [kotlinx.coroutines.sync.a] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        E e;
        ?? r4;
        C c;
        kotlinx.coroutines.sync.c cVar;
        kotlinx.coroutines.sync.a aVar;
        E e2;
        Throwable th;
        C c2;
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
                    C c3 = new C(this.o, (InterfaceC5025j0) element);
                    while (true) {
                        e = this.p;
                        AtomicReference atomicReference3 = e.a;
                        C c4 = (C) atomicReference3.get();
                        if (c4 != null && c3.a.compareTo(c4.a) < 0) {
                            throw new CancellationException("Current mutation had a higher priority");
                        }
                        while (!atomicReference3.compareAndSet(c4, c3)) {
                            if (atomicReference3.get() != c4) {
                                break;
                            }
                        }
                        if (c4 != null) {
                            c4.b.j(null);
                        }
                        this.n = c3;
                        kotlinx.coroutines.sync.c cVar2 = e.b;
                        this.j = cVar2;
                        kotlin.coroutines.jvm.internal.i iVar = this.q;
                        this.k = iVar;
                        this.l = e;
                        this.m = 1;
                        if (cVar2.d(this) != aVar2) {
                            r4 = iVar;
                            c = c3;
                            cVar = cVar2;
                        }
                    }
                    return aVar2;
                }
                if (r1 != 1) {
                    if (r1 != 2) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    e2 = (E) this.k;
                    aVar = this.j;
                    c2 = (C) this.n;
                    try {
                        androidx.glance.appwidget.protobuf.Z.e(obj);
                        atomicReference2 = e2.a;
                        while (!atomicReference2.compareAndSet(c2, null) && atomicReference2.get() == c2) {
                        }
                        ((kotlinx.coroutines.sync.c) aVar).f(null);
                        return obj;
                    } catch (Throwable th2) {
                        th = th2;
                        atomicReference = e2.a;
                        while (!atomicReference.compareAndSet(c2, null)) {
                        }
                        throw th;
                    }
                }
                E e3 = this.l;
                Function1 function1 = (Function1) this.k;
                ?? r5 = this.j;
                c = (C) this.n;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                e = e3;
                r4 = function1;
                cVar = r5;
                this.n = c;
                this.j = aVar;
                this.k = e;
                this.l = null;
                this.m = 2;
                Object objInvoke = r4.invoke(this);
                if (objInvoke != aVar2) {
                    e2 = e;
                    obj = objInvoke;
                    c2 = c;
                    atomicReference2 = e2.a;
                    while (!atomicReference2.compareAndSet(c2, null)) {
                    }
                    ((kotlinx.coroutines.sync.c) aVar).f(null);
                    return obj;
                }
                return aVar2;
            } catch (Throwable th3) {
                e2 = e;
                th = th3;
                c2 = c;
                atomicReference = e2.a;
                while (!atomicReference.compareAndSet(c2, null) && atomicReference.get() == c2) {
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
