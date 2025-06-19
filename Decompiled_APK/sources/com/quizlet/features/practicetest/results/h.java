package com.quizlet.features.practicetest.results;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.practicetest.results.data.k;
import com.quizlet.generated.enums.Q0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.features.practicetest.results.viewmodel.a k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(com.quizlet.features.practicetest.results.viewmodel.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        h hVar2 = new h(this.k, hVar);
        hVar2.j = obj;
        return hVar2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((Q0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        ((com.quizlet.features.practicetest.results.viewmodel.h) this.k).C(new k((Q0) this.j));
        return Unit.a;
    }
}
