package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.datastore.core.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1083o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1083o c1083o = new C1083o(2, hVar);
        c1083o.j = obj;
        return c1083o;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1083o) create((l0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        return Boolean.valueOf(!(((l0) this.j) instanceof a0));
    }
}
