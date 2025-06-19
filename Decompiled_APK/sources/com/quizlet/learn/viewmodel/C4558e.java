package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLog;
import com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.d0;

/* renamed from: com.quizlet.learn.viewmodel.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4558e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4558e(i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4558e(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4558e) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            i iVar = this.k;
            LearnOnboardingEventLogger learnOnboardingEventLogger = iVar.c;
            learnOnboardingEventLogger.getClass();
            LearnOnboardingEventLog.Companion companion = LearnOnboardingEventLog.b;
            com.braze.requests.framework.m mVar = new com.braze.requests.framework.m(3, iVar.f);
            companion.getClass();
            learnOnboardingEventLogger.a(LearnOnboardingEventLog.Companion.a("study_mode_button_clicked", mVar));
            Object yVar = iVar.l ? new com.quizlet.learn.data.onboarding.y(iVar.e, iVar.f, iVar.h, iVar.i, iVar.g, iVar.j, iVar.k) : new com.quizlet.learn.data.onboarding.x(iVar.e, iVar.f, iVar.h, iVar.i, iVar.g, iVar.j);
            d0 d0Var = iVar.n;
            this.j = 1;
            if (d0Var.emit(yVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
