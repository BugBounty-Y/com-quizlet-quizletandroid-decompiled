package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.core.a0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0231a0 extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ E0 k;
    public final /* synthetic */ C0247i0 l;
    public final /* synthetic */ Object m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0231a0(C0247i0 c0247i0, E0 e0, Object obj, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = e0;
        this.l = c0247i0;
        this.m = obj;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        Object obj = this.m;
        return new C0231a0(this.l, this.k, obj, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C0231a0) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        E0 e0 = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Z z = new Z(this.l, e0, this.m, null);
            this.j = 1;
            if (kotlinx.coroutines.E.m(z, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        e0.j();
        return Unit.a;
    }
}
