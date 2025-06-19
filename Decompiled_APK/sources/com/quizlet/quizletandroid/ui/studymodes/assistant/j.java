package com.quizlet.quizletandroid.ui.studymodes.assistant;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ LearningAssistantActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(LearningAssistantActivity learningAssistantActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = learningAssistantActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        j jVar = new j(this.k, hVar);
        jVar.j = obj;
        return jVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((com.quizlet.quizletandroid.ui.learnpaywall.l) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        boolean z = ((com.quizlet.quizletandroid.ui.learnpaywall.l) this.j).a;
        String str = LearningAssistantActivity.D;
        this.k.e0(z);
        return Unit.a;
    }
}
