package androidx.compose.animation.core;

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
public final class V extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.a j;
    public Object k;
    public W l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ W o;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public V(W w, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = w;
        this.p = (kotlin.coroutines.jvm.internal.i) function1;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        V v = new V(this.o, this.p, hVar);
        v.n = obj;
        return v;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((V) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v3, types: [kotlin.jvm.functions.Function1] */
    /* JADX WARN: Type inference failed for: r5v5, types: [kotlinx.coroutines.sync.a] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        W w;
        ?? r2;
        U u;
        kotlinx.coroutines.sync.c cVar;
        kotlinx.coroutines.sync.a aVar;
        W w2;
        Throwable th;
        U u2;
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
                    U u3 = new U((InterfaceC5025j0) element);
                    while (true) {
                        w = this.o;
                        AtomicReference atomicReference3 = w.a;
                        U u4 = (U) atomicReference3.get();
                        if (u4 != null && 1 - 1 < 0) {
                            throw new CancellationException("Current mutation had a higher priority");
                        }
                        while (!atomicReference3.compareAndSet(u4, u3)) {
                            if (atomicReference3.get() != u4) {
                                break;
                            }
                        }
                        if (u4 != null) {
                            u4.a.j(new MutationInterruptedException());
                        }
                        this.n = u3;
                        kotlinx.coroutines.sync.c cVar2 = w.b;
                        this.j = cVar2;
                        kotlin.coroutines.jvm.internal.i iVar = this.p;
                        this.k = iVar;
                        this.l = w;
                        this.m = 1;
                        if (cVar2.d(this) != aVar2) {
                            r2 = iVar;
                            u = u3;
                            cVar = cVar2;
                        }
                    }
                    return aVar2;
                }
                if (r1 != 1) {
                    if (r1 != 2) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    w2 = (W) this.k;
                    aVar = this.j;
                    u2 = (U) this.n;
                    try {
                        androidx.glance.appwidget.protobuf.Z.e(obj);
                        atomicReference2 = w2.a;
                        while (!atomicReference2.compareAndSet(u2, null) && atomicReference2.get() == u2) {
                        }
                        ((kotlinx.coroutines.sync.c) aVar).f(null);
                        return obj;
                    } catch (Throwable th2) {
                        th = th2;
                        atomicReference = w2.a;
                        while (!atomicReference.compareAndSet(u2, null)) {
                        }
                        throw th;
                    }
                }
                W w3 = this.l;
                Function1 function1 = (Function1) this.k;
                ?? r5 = this.j;
                u = (U) this.n;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                w = w3;
                r2 = function1;
                cVar = r5;
                this.n = u;
                this.j = aVar;
                this.k = w;
                this.l = null;
                this.m = 2;
                Object objInvoke = r2.invoke(this);
                if (objInvoke != aVar2) {
                    w2 = w;
                    obj = objInvoke;
                    u2 = u;
                    atomicReference2 = w2.a;
                    while (!atomicReference2.compareAndSet(u2, null)) {
                    }
                    ((kotlinx.coroutines.sync.c) aVar).f(null);
                    return obj;
                }
                return aVar2;
            } catch (Throwable th3) {
                w2 = w;
                th = th3;
                u2 = u;
                atomicReference = w2.a;
                while (!atomicReference.compareAndSet(u2, null) && atomicReference.get() == u2) {
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
