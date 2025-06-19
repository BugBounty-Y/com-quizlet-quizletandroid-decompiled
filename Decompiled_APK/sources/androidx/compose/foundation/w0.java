package androidx.compose.foundation;

import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class w0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.a j;
    public Object k;
    public y0 l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ y0 o;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public w0(y0 y0Var, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = y0Var;
        this.p = (kotlin.coroutines.jvm.internal.i) function1;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        w0 w0Var = new w0(this.o, this.p, hVar);
        w0Var.n = obj;
        return w0Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((w0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r3v10 */
    /* JADX WARN: Type inference failed for: r3v2 */
    /* JADX WARN: Type inference failed for: r3v3, types: [kotlin.jvm.functions.Function1] */
    /* JADX WARN: Type inference failed for: r5v4, types: [kotlinx.coroutines.sync.a] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        y0 y0Var;
        ?? r3;
        v0 v0Var;
        kotlinx.coroutines.sync.c cVar;
        kotlinx.coroutines.sync.a aVar;
        y0 y0Var2;
        Throwable th;
        v0 v0Var2;
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
                    v0 v0Var3 = new v0(u0.a, (InterfaceC5025j0) element);
                    y0Var = this.o;
                    y0.a(y0Var, v0Var3);
                    this.n = v0Var3;
                    kotlinx.coroutines.sync.c cVar2 = y0Var.b;
                    this.j = cVar2;
                    kotlin.coroutines.jvm.internal.i iVar = this.p;
                    this.k = iVar;
                    this.l = y0Var;
                    this.m = 1;
                    if (cVar2.d(this) != aVar2) {
                        r3 = iVar;
                        v0Var = v0Var3;
                        cVar = cVar2;
                    }
                    return aVar2;
                }
                if (r1 != 1) {
                    if (r1 != 2) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    y0Var2 = (y0) this.k;
                    aVar = this.j;
                    v0Var2 = (v0) this.n;
                    try {
                        androidx.glance.appwidget.protobuf.Z.e(obj);
                        atomicReference2 = y0Var2.a;
                        while (!atomicReference2.compareAndSet(v0Var2, null) && atomicReference2.get() == v0Var2) {
                        }
                        ((kotlinx.coroutines.sync.c) aVar).f(null);
                        return obj;
                    } catch (Throwable th2) {
                        th = th2;
                        atomicReference = y0Var2.a;
                        while (!atomicReference.compareAndSet(v0Var2, null)) {
                        }
                        throw th;
                    }
                }
                y0 y0Var3 = this.l;
                Function1 function1 = (Function1) this.k;
                ?? r5 = this.j;
                v0Var = (v0) this.n;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                y0Var = y0Var3;
                r3 = function1;
                cVar = r5;
                this.n = v0Var;
                this.j = aVar;
                this.k = y0Var;
                this.l = null;
                this.m = 2;
                Object objInvoke = r3.invoke(this);
                if (objInvoke != aVar2) {
                    y0Var2 = y0Var;
                    obj = objInvoke;
                    v0Var2 = v0Var;
                    atomicReference2 = y0Var2.a;
                    while (!atomicReference2.compareAndSet(v0Var2, null)) {
                    }
                    ((kotlinx.coroutines.sync.c) aVar).f(null);
                    return obj;
                }
                return aVar2;
            } catch (Throwable th3) {
                y0Var2 = y0Var;
                th = th3;
                v0Var2 = v0Var;
                atomicReference = y0Var2.a;
                while (!atomicReference.compareAndSet(v0Var2, null) && atomicReference.get() == v0Var2) {
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
