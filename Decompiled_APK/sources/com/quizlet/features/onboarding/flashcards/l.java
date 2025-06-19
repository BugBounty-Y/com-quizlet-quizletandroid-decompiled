package com.quizlet.features.onboarding.flashcards;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.model.OnboardingFlashcardsEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ n k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(n nVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = nVar;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new l(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            n nVar = this.k;
            j jVar = nVar.c;
            jVar.getClass();
            OnboardingFlashcardsEventLog.b.getClass();
            Intrinsics.checkNotNullParameter("onboarding_flashcards_answer", "action");
            OnboardingFlashcardsEventLog.Payload createEvent = new OnboardingFlashcardsEventLog.Payload(null, 1, null);
            Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
            createEvent.setOnboardingFlashcardsAcknowledge(Boolean.valueOf(this.l));
            Unit unit = Unit.a;
            OnboardingFlashcardsEventLog onboardingFlashcardsEventLog = new OnboardingFlashcardsEventLog(createEvent);
            onboardingFlashcardsEventLog.setAction("onboarding_flashcards_answer");
            jVar.a.l(onboardingFlashcardsEventLog);
            this.j = 1;
            if (n.A(nVar, this) == aVar) {
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
