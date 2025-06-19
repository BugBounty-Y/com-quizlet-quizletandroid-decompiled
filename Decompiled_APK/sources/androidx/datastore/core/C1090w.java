package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.datastore.core.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1090w extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ G k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1090w(G g, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C1090w(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C1090w) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            return obj;
        }
        androidx.glance.appwidget.protobuf.Z.e(obj);
        this.j = 1;
        Object objInvoke = this.k.invoke(this);
        return objInvoke == aVar ? aVar : objInvoke;
    }
}
