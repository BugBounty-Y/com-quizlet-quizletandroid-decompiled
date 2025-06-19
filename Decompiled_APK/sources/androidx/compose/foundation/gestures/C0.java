package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class C0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ long k;
    public final /* synthetic */ D0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0(D0 d0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = d0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0 c0 = new C0(this.l, hVar);
        c0.k = ((androidx.compose.ui.geometry.b) obj).a;
        return c0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        long j = ((androidx.compose.ui.geometry.b) obj).a;
        C0 c0 = new C0(this.l, (kotlin.coroutines.h) obj2);
        c0.k = j;
        return c0.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            return obj;
        }
        androidx.glance.appwidget.protobuf.Z.e(obj);
        long j = this.k;
        L0 l0 = this.l.C;
        this.j = 1;
        Object objA = AbstractC0349s0.a(l0, j, this);
        return objA == aVar ? aVar : objA;
    }
}
