package kotlinx.coroutines.channels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ x l;
    public final /* synthetic */ Object m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(x xVar, Object obj, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = xVar;
        this.m = obj;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        q qVar = new q(this.l, this.m, hVar);
        qVar.k = obj;
        return qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                x xVar = this.l;
                Object obj2 = this.m;
                kotlin.p pVar = kotlin.r.b;
                this.j = 1;
                if (xVar.s(obj2, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            objB = Unit.a;
            kotlin.p pVar2 = kotlin.r.b;
        } catch (Throwable th) {
            kotlin.p pVar3 = kotlin.r.b;
            objB = Z.b(th);
        }
        return new o(!(objB instanceof kotlin.q) ? Unit.a : new m(kotlin.r.a(objB)));
    }
}
