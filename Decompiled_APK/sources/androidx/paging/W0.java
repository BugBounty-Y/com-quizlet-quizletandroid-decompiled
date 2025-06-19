package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class W0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ kotlinx.coroutines.channels.h l;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public W0(kotlinx.coroutines.channels.h hVar, Function2 function2, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.l = hVar;
        this.m = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        W0 w0 = new W0(this.l, this.m, hVar);
        w0.k = obj;
        return w0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((W0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r5v3, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            a1 a1Var = new a1((kotlinx.coroutines.C) this.k, this.l);
            this.j = 1;
            if (this.m.invoke(a1Var, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
