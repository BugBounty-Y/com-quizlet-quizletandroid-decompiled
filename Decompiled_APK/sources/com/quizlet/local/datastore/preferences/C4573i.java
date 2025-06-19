package com.quizlet.local.datastore.preferences;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.local.datastore.preferences.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4573i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ androidx.datastore.preferences.core.f k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4573i(androidx.datastore.preferences.core.f fVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = fVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4573i c4573i = new C4573i(this.k, this.l, hVar);
        c4573i.j = obj;
        return c4573i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4573i) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        ((androidx.datastore.preferences.core.b) this.j).e(this.k, new Long(this.l));
        return Unit.a;
    }
}
