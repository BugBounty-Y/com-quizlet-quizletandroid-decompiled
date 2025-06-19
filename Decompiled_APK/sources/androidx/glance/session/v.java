package androidx.glance.session;

import androidx.glance.appwidget.C1182m;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ SessionWorker k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(SessionWorker sessionWorker, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = sessionWorker;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        v vVar = new v(this.k, hVar);
        vVar.j = obj;
        return vVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((v) create((o) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        o oVar = (o) this.j;
        return (C1182m) oVar.a.get(this.k.k);
    }
}
