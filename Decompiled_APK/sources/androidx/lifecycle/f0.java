package androidx.lifecycle;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class f0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.a j;
    public kotlin.coroutines.jvm.internal.i k;
    public int l;
    public final /* synthetic */ kotlinx.coroutines.sync.c m;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public f0(kotlinx.coroutines.sync.c cVar, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = cVar;
        this.n = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f0(this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v2, types: [kotlin.jvm.functions.Function2] */
    /* JADX WARN: Type inference failed for: r1v6 */
    /* JADX WARN: Type inference failed for: r1v7 */
    /* JADX WARN: Type inference failed for: r3v3, types: [kotlinx.coroutines.sync.a] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlinx.coroutines.sync.c cVar;
        ?? r1;
        kotlinx.coroutines.sync.a aVar;
        Throwable th;
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                cVar = this.m;
                this.j = cVar;
                kotlin.coroutines.jvm.internal.i iVar = this.n;
                this.k = iVar;
                this.l = 1;
                r1 = iVar;
                if (cVar.d(this) != aVar2) {
                }
                return aVar2;
            }
            if (i != 1) {
                if (i != 2) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                aVar = this.j;
                try {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    Unit unit = Unit.a;
                    ((kotlinx.coroutines.sync.c) aVar).f(null);
                    return Unit.a;
                } catch (Throwable th2) {
                    th = th2;
                    ((kotlinx.coroutines.sync.c) aVar).f(null);
                    throw th;
                }
            }
            Function2 function2 = (Function2) this.k;
            ?? r3 = this.j;
            androidx.glance.appwidget.protobuf.Z.e(obj);
            cVar = r3;
            r1 = function2;
            e0 e0Var = new e0(r1, null);
            this.j = cVar;
            this.k = null;
            this.l = 2;
            if (kotlinx.coroutines.E.m(e0Var, this) != aVar2) {
                aVar = cVar;
                Unit unit2 = Unit.a;
                ((kotlinx.coroutines.sync.c) aVar).f(null);
                return Unit.a;
            }
            return aVar2;
        } catch (Throwable th3) {
            aVar = cVar;
            th = th3;
            ((kotlinx.coroutines.sync.c) aVar).f(null);
            throw th;
        }
    }
}
