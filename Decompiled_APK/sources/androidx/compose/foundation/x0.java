package androidx.compose.foundation;

import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class x0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.a j;
    public Object k;
    public Object l;
    public y0 m;
    public int n;
    public /* synthetic */ Object o;
    public final /* synthetic */ u0 p;
    public final /* synthetic */ y0 q;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i r;
    public final /* synthetic */ Object s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public x0(u0 u0Var, y0 y0Var, Function2 function2, Object obj, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.p = u0Var;
        this.q = y0Var;
        this.r = (kotlin.coroutines.jvm.internal.i) function2;
        this.s = obj;
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        x0 x0Var = new x0(this.p, this.q, this.r, this.s, hVar);
        x0Var.o = obj;
        return x0Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((x0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r5v3 */
    /* JADX WARN: Type inference failed for: r5v4, types: [kotlin.jvm.functions.Function2] */
    /* JADX WARN: Type inference failed for: r5v7 */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        y0 y0Var;
        Object obj2;
        v0 v0Var;
        kotlinx.coroutines.sync.a aVar;
        ?? r5;
        y0 y0Var2;
        Throwable th;
        v0 v0Var2;
        AtomicReference atomicReference;
        AtomicReference atomicReference2;
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        ?? r1 = this.n;
        try {
            try {
                if (r1 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    CoroutineContext.Element element = ((kotlinx.coroutines.C) this.o).getCoroutineContext().get(C5023i0.a);
                    Intrinsics.d(element);
                    v0 v0Var3 = new v0(this.p, (InterfaceC5025j0) element);
                    y0Var = this.q;
                    y0.a(y0Var, v0Var3);
                    this.o = v0Var3;
                    kotlinx.coroutines.sync.c cVar = y0Var.b;
                    this.j = cVar;
                    kotlin.coroutines.jvm.internal.i iVar = this.r;
                    this.k = iVar;
                    Object obj3 = this.s;
                    this.l = obj3;
                    this.m = y0Var;
                    this.n = 1;
                    if (cVar.d(this) != aVar2) {
                        obj2 = obj3;
                        v0Var = v0Var3;
                        aVar = cVar;
                        r5 = iVar;
                    }
                    return aVar2;
                }
                if (r1 != 1) {
                    if (r1 != 2) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    y0Var2 = (y0) this.k;
                    aVar = this.j;
                    v0Var2 = (v0) this.o;
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
                y0 y0Var3 = this.m;
                obj2 = this.l;
                Function2 function2 = (Function2) this.k;
                kotlinx.coroutines.sync.a aVar3 = this.j;
                v0Var = (v0) this.o;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                y0Var = y0Var3;
                aVar = aVar3;
                r5 = function2;
                this.o = v0Var;
                this.j = aVar;
                this.k = y0Var;
                this.l = null;
                this.m = null;
                this.n = 2;
                Object objInvoke = r5.invoke(obj2, this);
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
        } catch (Throwable th4) {
            ((kotlinx.coroutines.sync.c) r1).f(null);
            throw th4;
        }
    }
}
