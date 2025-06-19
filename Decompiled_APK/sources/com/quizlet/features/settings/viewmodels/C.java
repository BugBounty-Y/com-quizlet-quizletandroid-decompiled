package com.quizlet.features.settings.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ I k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(I i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C c = new C(this.k, hVar);
        c.j = obj;
        return c;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.j;
        I i = this.k;
        kotlinx.coroutines.E.A(c, null, null, new z(i, null), 3);
        kotlinx.coroutines.E.A(c, null, null, new A(i, null), 3);
        kotlinx.coroutines.E.A(c, null, null, new B(i, null), 3);
        return Unit.a;
    }
}
