package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.fragment.app.Fragment;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogData;
import com.quizlet.eventlogger.features.basequestion.QuestionEventSideData;
import com.quizlet.eventlogger.model.QuestionEventLog;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableQuestionMetadata;
import java.io.File;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class P6 {
    public static dagger.hilt.android.internal.lifecycle.f a(androidx.activity.s sVar, androidx.lifecycle.y0 y0Var) {
        C4622e c4622e = (C4622e) ((dagger.hilt.android.internal.lifecycle.a) K6.b(dagger.hilt.android.internal.lifecycle.a.class, sVar));
        dagger.internal.b bVarC = c4622e.c();
        com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c(c4622e.b, c4622e.c);
        y0Var.getClass();
        return new dagger.hilt.android.internal.lifecycle.f(bVarC, y0Var, cVar);
    }

    public static dagger.hilt.android.internal.lifecycle.f b(Fragment fragment, androidx.lifecycle.y0 y0Var) {
        C4622e c4622e = ((com.quizlet.quizletandroid.j) ((dagger.hilt.android.internal.lifecycle.b) K6.b(dagger.hilt.android.internal.lifecycle.b.class, fragment))).d;
        dagger.internal.b bVarC = c4622e.c();
        com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c(c4622e.b, c4622e.c);
        y0Var.getClass();
        return new dagger.hilt.android.internal.lifecycle.f(bVarC, y0Var, cVar);
    }

    public static void c(com.quizlet.features.match.logging.b bVar, com.quizlet.features.match.logging.c matchQuestionActionLogData, String questionSessionId, String action, Boolean bool, com.quizlet.generated.enums.A1 a1, int i) {
        kotlin.v vVar;
        assistantMode.enums.k kVar = assistantMode.enums.k.c;
        Boolean bool2 = (i & 8) != 0 ? null : bool;
        com.quizlet.generated.enums.A1 a12 = (i & 16) != 0 ? null : a1;
        assistantMode.enums.k kVar2 = (i & 32) != 0 ? null : kVar;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(matchQuestionActionLogData, "matchQuestionActionLogData");
        Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
        Intrinsics.checkNotNullParameter(action, "action");
        QuestionEventLogData.a.getClass();
        MixedOptionMatchingStudiableQuestion question = matchQuestionActionLogData.a;
        Intrinsics.checkNotNullParameter(question, "question");
        long j = question.c.b;
        Long lValueOf = j < 0 ? null : Long.valueOf(j);
        ArrayList arrayList = question.b;
        kotlin.v vVarB = QuestionEventLogData.Companion.b((QuestionSectionData) arrayList.get(matchQuestionActionLogData.b));
        boolean zBooleanValue = ((Boolean) vVarB.a).booleanValue();
        boolean zBooleanValue2 = ((Boolean) vVarB.b).booleanValue();
        boolean zBooleanValue3 = ((Boolean) vVarB.c).booleanValue();
        StudiableQuestionMetadata studiableQuestionMetadata = question.c;
        Boolean bool3 = bool2;
        QuestionEventSideData questionEventSideData = new QuestionEventSideData(AbstractC3106b5.g(studiableQuestionMetadata.c), zBooleanValue, zBooleanValue2, zBooleanValue3);
        Integer num = matchQuestionActionLogData.c;
        if (num != null) {
            vVar = QuestionEventLogData.Companion.b((QuestionSectionData) arrayList.get(num.intValue()));
        } else {
            Boolean bool4 = Boolean.FALSE;
            vVar = new kotlin.v(bool4, bool4, bool4);
        }
        QuestionEventLogData questionEventLogData = new QuestionEventLogData(lValueOf, j, questionEventSideData, new QuestionEventSideData(AbstractC3106b5.g(studiableQuestionMetadata.d), ((Boolean) vVar.a).booleanValue(), ((Boolean) vVar.b).booleanValue(), ((Boolean) vVar.c).booleanValue()), QuestionEventLogData.Companion.c(studiableQuestionMetadata.f));
        Integer numValueOf = bool3 != null ? Integer.valueOf(bool3.booleanValue() ? 1 : 0) : null;
        com.quizlet.features.infra.basestudy.manager.f fVar = bVar.a;
        com.quizlet.features.match.logging.a aVar = bVar.b;
        String studySessionId = fVar.t;
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
        Intrinsics.checkNotNullParameter(action, "action");
        Intrinsics.checkNotNullParameter(questionEventLogData, "questionEventLogData");
        QuestionEventSideData promptSideData = questionEventLogData.getPromptSideData();
        QuestionEventSideData answerSideData = questionEventLogData.getAnswerSideData();
        aVar.a.v(QuestionEventLog.Companion.b(QuestionEventLog.b, action, studySessionId, questionSessionId, questionEventLogData.getId(), questionEventLogData.getLocalId(), 2, promptSideData.getHasText(), promptSideData.getHasImage(), promptSideData.getHasAudio(), answerSideData.getHasText(), answerSideData.getHasImage(), answerSideData.getHasAudio(), null, promptSideData.getSide(), numValueOf, null, questionEventLogData.getQuestionSource(), null, a12, kVar2, 503316480));
    }

    public static final File d(Context context, String name) {
        Intrinsics.checkNotNullParameter(context, "<this>");
        Intrinsics.checkNotNullParameter(name, "name");
        return K6.a(context, name + ".preferences_pb");
    }
}
