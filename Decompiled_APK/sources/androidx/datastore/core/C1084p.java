package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.datastore.core.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1084p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ l0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1084p(l0 l0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = l0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1084p c1084p = new C1084p(this.k, hVar);
        c1084p.j = obj;
        return c1084p;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1084p) create((l0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        l0 l0Var = (l0) this.j;
        return Boolean.valueOf((l0Var instanceof C1071c) && l0Var.a <= this.k.a);
    }
}
