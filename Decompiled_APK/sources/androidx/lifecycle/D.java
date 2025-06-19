package androidx.lifecycle;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ E k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(E e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        D d = new D(this.k, hVar);
        d.j = obj;
        return d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.j;
        E e = this.k;
        C c2 = e.a;
        if (((L) c2).d.compareTo(B.b) >= 0) {
            c2.a(e);
        } else {
            kotlinx.coroutines.E.h(c.getCoroutineContext(), null);
        }
        return Unit.a;
    }
}
