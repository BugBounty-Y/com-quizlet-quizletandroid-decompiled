package androidx.glance.session;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public final /* synthetic */ K j;
    public final /* synthetic */ SessionWorker k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(SessionWorker sessionWorker, K k, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.j = k;
        this.k = sessionWorker;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new s(this.k, this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((s) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.j.b(this.k.i.c);
        return Unit.a;
    }
}
