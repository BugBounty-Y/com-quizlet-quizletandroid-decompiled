package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class H extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ I j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H(I i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new H(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((H) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        this.j.getClass();
        return Unit.a;
    }
}
