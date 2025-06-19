package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.core.e0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0239e0 extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ Object k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ C0247i0 m;
    public final /* synthetic */ E0 n;
    public final /* synthetic */ float o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0239e0(Object obj, Object obj2, C0247i0 c0247i0, E0 e0, float f, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = obj;
        this.l = obj2;
        this.m = c0247i0;
        this.n = e0;
        this.o = f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C0239e0(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C0239e0) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0237d0 c0237d0 = new C0237d0(this.k, this.l, this.m, this.n, this.o, null);
            this.j = 1;
            if (kotlinx.coroutines.E.m(c0237d0, this) == aVar) {
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
