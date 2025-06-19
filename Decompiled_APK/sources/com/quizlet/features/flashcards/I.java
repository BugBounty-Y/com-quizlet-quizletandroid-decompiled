package com.quizlet.features.flashcards;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.flashcards.FlashcardsEventLog;
import com.quizlet.eventlogger.features.flashcards.FlashcardsEventPayload;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class I extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ S k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(S s, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new I(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((I) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            S s = this.k;
            com.quizlet.features.flashcards.logging.a aVar2 = s.h;
            aVar2.getClass();
            FlashcardsEventLog.b.getClass();
            Intrinsics.checkNotNullParameter("flashcards_next_action_button_clicked", "action");
            FlashcardsEventPayload createEvent = new FlashcardsEventPayload(null, null, null, null, 15, null);
            createEvent.setSortingMode("REVIEW_MODE");
            Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
            createEvent.setNextAction("sort_flashcards");
            createEvent.setScreenName("results");
            Unit unit = Unit.a;
            FlashcardsEventLog flashcardsEventLog = new FlashcardsEventLog(createEvent);
            flashcardsEventLog.setAction("flashcards_next_action_button_clicked");
            aVar2.a.l(flashcardsEventLog);
            this.j = 1;
            com.quizlet.features.flashcards.engine.h hVar = s.c;
            com.quizlet.features.infra.models.flashcards.d dVarA = com.quizlet.features.infra.models.flashcards.d.a(hVar.d(), null, null, false, false, 0L, (!hVar.e() ? com.quizlet.features.infra.models.flashcards.c.c : com.quizlet.features.infra.models.flashcards.c.d).a, 255);
            com.quizlet.features.flashcards.logging.a.a(hVar.d, "toggle_flashcards_movement_style", null, null, null, 62);
            hVar.q(dVarA);
            Object objI = hVar.i(this);
            if (objI != aVar) {
                objI = Unit.a;
            }
            if (objI == aVar) {
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
