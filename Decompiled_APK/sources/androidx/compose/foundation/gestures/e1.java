package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class e1 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ C0326g0 j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e1(C0326g0 c0326g0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = c0326g0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e1(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e1) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        C0326g0 c0326g0 = this.j;
        c0326g0.b = true;
        c0326g0.d.f(null);
        return Unit.a;
    }
}
