package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.t0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1341t0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ C1343u0 j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1341t0(C1343u0 c1343u0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = c1343u0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1341t0(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1341t0) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        this.j.g.o(new Integer(0));
        return Unit.a;
    }
}
