package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.core.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0234c extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public final /* synthetic */ C0238e j;
    public final /* synthetic */ Object k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0234c(C0238e c0238e, Object obj, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.j = c0238e;
        this.k = obj;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C0234c(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C0234c) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        C0238e c0238e = this.j;
        C0238e.b(c0238e);
        Object objA = C0238e.a(c0238e, this.k);
        ((androidx.compose.runtime.L0) c0238e.c.b).setValue(objA);
        ((androidx.compose.runtime.L0) c0238e.e).setValue(objA);
        return Unit.a;
    }
}
