package com.quizlet.features.onboarding.survey;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ OnboardingSurveyActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(OnboardingSurveyActivity onboardingSurveyActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = onboardingSurveyActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        c cVar = new c(this.k, hVar);
        cVar.j = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((l) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (!(((l) this.j) instanceof l)) {
            throw new NoWhenBranchMatchedException();
        }
        this.k.finish();
        return Unit.a;
    }
}
