package com.quizlet.local.datastore.preferences;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class Y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ androidx.datastore.preferences.core.f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Y(androidx.datastore.preferences.core.f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        Y y = new Y(this.k, hVar);
        y.j = obj;
        return y;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Y) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        ((androidx.datastore.preferences.core.b) this.j).e(this.k, new Integer(0));
        return Unit.a;
    }
}
