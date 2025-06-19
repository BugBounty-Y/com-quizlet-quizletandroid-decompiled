package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.datastore.core.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1074f extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C1074f(1, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C1074f) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            this.j = 1;
            throw null;
        }
        if (i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        androidx.glance.appwidget.protobuf.Z.e(obj);
        return Unit.a;
    }
}
