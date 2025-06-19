package com.quizlet.eventlogger.features.practicetest;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class PracticeTestEventLogger {

    @NotNull
    private final EventLogger eventLogger;

    public PracticeTestEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a(PracticeTestEventLog practiceTestEventLog) {
        this.eventLogger.l(practiceTestEventLog);
    }

    public final void b(final int i, final int i2, final String practiceTestSessionId, final String questionBankId, final String screen, final ArrayList defaultQuestionFormats) {
        Intrinsics.checkNotNullParameter(defaultQuestionFormats, "defaultQuestionFormats");
        Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        Intrinsics.checkNotNullParameter(screen, "screen");
        PracticeTestEventLog.Companion companion = PracticeTestEventLog.b;
        Function1 function1 = new Function1() { // from class: com.quizlet.eventlogger.features.practicetest.b
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                PracticeTestEventLog.Payload createEvent = (PracticeTestEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPracticeTestSessionId(practiceTestSessionId);
                createEvent.setQuestionBankId(questionBankId);
                createEvent.setScreen(screen);
                createEvent.setAdditionalInfo(new PracticeTestEventLog.AdditionalInfo(null, Integer.valueOf(i), Integer.valueOf(i2), defaultQuestionFormats.toString(), null, null, null, null, null, 497, null));
                return Unit.a;
            }
        };
        companion.getClass();
        a(PracticeTestEventLog.Companion.a("test_options_modal_opened", function1));
    }

    public final void c(int i, ArrayList questionFormats, String practiceTestSessionId, String questionBankId, String screen) {
        Intrinsics.checkNotNullParameter(questionFormats, "questionFormats");
        Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        Intrinsics.checkNotNullParameter(screen, "screen");
        PracticeTestEventLog.Companion companion = PracticeTestEventLog.b;
        c cVar = new c(i, 1, practiceTestSessionId, questionBankId, screen, questionFormats);
        companion.getClass();
        a(PracticeTestEventLog.Companion.a("take_test_button_clicked", cVar));
    }
}
