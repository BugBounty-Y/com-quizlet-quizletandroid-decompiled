package com.quizlet.quizletandroid.initializers.app;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.C4135i0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.repository.login.a k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(com.quizlet.data.repository.login.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        j jVar = new j(this.k, hVar);
        jVar.j = obj;
        return jVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C4135i0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        ((com.quizlet.usecase.a) ((com.quizlet.usecase.b) this.k.b)).a((C4135i0) this.j);
        return Unit.a;
    }
}
