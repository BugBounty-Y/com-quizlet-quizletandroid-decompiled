package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class A0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ D0 k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A0(D0 d0, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = d0;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new A0(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((A0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            L0 l0 = this.k.C;
            androidx.compose.foundation.u0 u0Var = androidx.compose.foundation.u0.b;
            C0363z0 c0363z0 = new C0363z0(this.l, null);
            this.j = 1;
            if (l0.e(u0Var, c0363z0, this) == aVar) {
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
