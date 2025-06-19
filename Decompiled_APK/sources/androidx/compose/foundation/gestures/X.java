package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class X extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Y l;
    public final /* synthetic */ long m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public X(Y y, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = y;
        this.m = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        X x = new X(this.l, this.m, hVar);
        x.k = obj;
        return x;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((X) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            Y y = this.l;
            kotlin.jvm.functions.c cVar = y.B;
            long jF = androidx.compose.ui.unit.o.f(this.m, y.C ? -1.0f : 1.0f);
            EnumC0320d0 enumC0320d0 = y.y;
            S s = U.a;
            Float f = new Float(enumC0320d0 == EnumC0320d0.a ? androidx.compose.ui.unit.o.c(jF) : androidx.compose.ui.unit.o.b(jF));
            this.j = 1;
            if (cVar.invoke(c, f, this) == aVar) {
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
