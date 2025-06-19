package com.quizlet.features.flashcards;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.flashcards.FlashcardsEventLog;
import com.quizlet.eventlogger.features.flashcards.FlashcardsEventPayload;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class F extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ S k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(S s, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new F(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((F) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            S s = this.k;
            com.quizlet.features.flashcards.logging.a aVar2 = s.h;
            String studyModeScreen = S.C(s);
            com.quizlet.features.flashcards.engine.h hVar = s.c;
            boolean z = hVar.d().b() == com.quizlet.features.infra.models.flashcards.c.c;
            aVar2.getClass();
            Intrinsics.checkNotNullParameter(studyModeScreen, "studyModeScreen");
            FlashcardsEventLog.b.getClass();
            Intrinsics.checkNotNullParameter("flashcards_next_action_button_clicked", "action");
            FlashcardsEventPayload createEvent = new FlashcardsEventPayload(null, null, null, null, 15, null);
            createEvent.setSortingMode(z ? "QUIZ_MODE" : "REVIEW_MODE");
            Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
            createEvent.setNextAction("restart_flashcards");
            createEvent.setScreenName(studyModeScreen);
            Unit unit = Unit.a;
            FlashcardsEventLog flashcardsEventLog = new FlashcardsEventLog(createEvent);
            flashcardsEventLog.setAction("flashcards_next_action_button_clicked");
            aVar2.a.l(flashcardsEventLog);
            this.j = 1;
            if (hVar.i(this) == aVar) {
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
