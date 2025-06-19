package com.quizlet.features.questiontypes.grading;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.TextGradingEventLog;
import com.quizlet.generated.enums.EnumC4508o1;
import com.quizlet.generated.enums.Q1;
import com.quizlet.studiablemodels.grading.PLongtextGradingResult;
import java.sql.Date;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final EventLogger a;
    public String b;
    public Long c;

    public a(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public final void a(PLongtextGradingResult gradedAnswer, String expectedAnswerText, String submittedAnswerText, long j) {
        Intrinsics.checkNotNullParameter(gradedAnswer, "gradedAnswer");
        Intrinsics.checkNotNullParameter(expectedAnswerText, "expectedAnswer");
        Intrinsics.checkNotNullParameter(submittedAnswerText, "submittedAnswer");
        TextGradingEventLog.Companion companion = TextGradingEventLog.b;
        String questionSessionId = this.b;
        if (questionSessionId == null) {
            Intrinsics.m("questionSessionId");
            throw null;
        }
        String studySessionId = String.valueOf(this.c);
        EnumC4508o1 grade = gradedAnswer.a;
        companion.getClass();
        Intrinsics.checkNotNullParameter(expectedAnswerText, "expectedAnswerText");
        Intrinsics.checkNotNullParameter(submittedAnswerText, "submittedAnswerText");
        Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(grade, "grade");
        Q1 q1 = Q1.GRADE_TEXT;
        TextGradingEventLog textGradingEventLog = new TextGradingEventLog();
        textGradingEventLog.setAction(q1.a());
        textGradingEventLog.setPayload(new TextGradingEventLog.Payload(q1.a(), questionSessionId, studySessionId, null, expectedAnswerText, submittedAnswerText, gradedAnswer.c, null, grade.a(), gradedAnswer.e, Double.valueOf(gradedAnswer.b), gradedAnswer.d, Boolean.TRUE, null, 8328, null));
        textGradingEventLog.setTimestamp(new Date(j));
        this.a.v(textGradingEventLog);
    }

    public final void b(long j, boolean z) {
        TextGradingEventLog.Companion companion = TextGradingEventLog.b;
        String questionSessionId = this.b;
        if (questionSessionId == null) {
            Intrinsics.m("questionSessionId");
            throw null;
        }
        String studySessionId = String.valueOf(this.c);
        companion.getClass();
        Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Q1 q1 = Q1.REQUEST_END;
        TextGradingEventLog textGradingEventLog = new TextGradingEventLog();
        textGradingEventLog.setAction(q1.a());
        textGradingEventLog.setPayload(new TextGradingEventLog.Payload(q1.a(), questionSessionId, studySessionId, null, null, null, null, null, null, null, null, null, Boolean.valueOf(z), null, 12280, null));
        textGradingEventLog.setTimestamp(new Date(j));
        this.a.v(textGradingEventLog);
    }

    public final void c(long j) {
        TextGradingEventLog.Companion companion = TextGradingEventLog.b;
        String questionSessionId = this.b;
        if (questionSessionId == null) {
            Intrinsics.m("questionSessionId");
            throw null;
        }
        String studySessionId = String.valueOf(this.c);
        companion.getClass();
        Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Q1 q1 = Q1.REQUEST_START;
        TextGradingEventLog textGradingEventLog = new TextGradingEventLog();
        textGradingEventLog.setAction(q1.a());
        textGradingEventLog.setPayload(new TextGradingEventLog.Payload(q1.a(), questionSessionId, studySessionId, null, null, null, null, null, null, null, null, null, null, null, 16376, null));
        textGradingEventLog.setTimestamp(new Date(j));
        this.a.v(textGradingEventLog);
    }
}
