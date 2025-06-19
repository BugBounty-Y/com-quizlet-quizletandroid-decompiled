package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.core.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0236d extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public final /* synthetic */ C0238e j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0236d(C0238e c0238e, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.j = c0238e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C0236d(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C0236d) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        C0238e.b(this.j);
        return Unit.a;
    }
}
