package com.quizlet.eventlogger.features.study;

import assistantMode.enums.k;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogData;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogger;
import com.quizlet.eventlogger.features.basequestion.QuestionEventSideData;
import com.quizlet.eventlogger.model.QuestionEventLog;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.O1;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class StudySessionQuestionEventLogger implements QuestionEventLogger, TextGradingEventLogger {

    @NotNull
    private final EventLogger eventLogger;
    private String studySessionId;

    @Metadata
    @InterfaceC4935d
    public static final class Factory {

        @NotNull
        private final EventLogger eventLogger;

        public Factory(@NotNull EventLogger eventLogger) {
            Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
            this.eventLogger = eventLogger;
        }

        public final StudySessionQuestionEventLogger a() {
            return new StudySessionQuestionEventLogger(this.eventLogger);
        }
    }

    public StudySessionQuestionEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    @Override // com.quizlet.eventlogger.features.basequestion.QuestionEventLogger
    public final void a(String questionSessionId, String action, QuestionEventLogData questionEventLogData, int i, Integer num, String str, O1 o1, String str2, A1 a1, k kVar) {
        Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
        Intrinsics.checkNotNullParameter(action, "action");
        Intrinsics.checkNotNullParameter(questionEventLogData, "questionEventLogData");
        String studySessionId = this.studySessionId;
        if (studySessionId == null) {
            return;
        }
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
        Intrinsics.checkNotNullParameter(action, "action");
        Intrinsics.checkNotNullParameter(questionEventLogData, "questionEventLogData");
        QuestionEventSideData promptSideData = questionEventLogData.getPromptSideData();
        QuestionEventSideData answerSideData = questionEventLogData.getAnswerSideData();
        this.eventLogger.v(QuestionEventLog.Companion.b(QuestionEventLog.b, action, studySessionId, questionSessionId, questionEventLogData.getId(), questionEventLogData.getLocalId(), i, promptSideData.getHasText(), promptSideData.getHasImage(), promptSideData.getHasAudio(), answerSideData.getHasText(), answerSideData.getHasImage(), answerSideData.getHasAudio(), o1, promptSideData.getSide(), num, str, questionEventLogData.getQuestionSource(), str2, a1, kVar, 100663296));
    }

    public final void b(String studySessionId) {
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        this.studySessionId = studySessionId;
    }
}
