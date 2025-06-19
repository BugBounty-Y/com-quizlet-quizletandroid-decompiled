package com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.L6;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBQuestionAttribute;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.O0;
import com.quizlet.generated.enums.O1;
import com.quizlet.infra.legacysyncengine.managers.i;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import com.quizlet.studiablemodels.StudiableQuestion;
import com.quizlet.studiablemodels.StudiableQuestionMetadata;
import com.quizlet.studiablemodels.WrittenStudiableQuestion;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final UserInfoCache a;
    public final i b;
    public Long c;
    public A1 d;

    public a(UserInfoCache userInfoCache, i modelSaveManager) {
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(modelSaveManager, "modelSaveManager");
        this.a = userInfoCache;
        this.b = modelSaveManager;
    }

    public final void a(long j, A1 studyModeType) {
        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
        this.c = Long.valueOf(j);
        this.d = studyModeType;
    }

    public final DBAnswer b(StudiableQuestion question, int i, long j) {
        Intrinsics.checkNotNullParameter(question, "question");
        Long l = this.c;
        if (l == null) {
            throw new IllegalStateException("sessionId should never be empty");
        }
        DBAnswer dBAnswer = new DBAnswer(l.longValue(), j, question.a().b, this.d, L6.c(question.a().a).a, i, this.a.getPersonId(), AbstractC3106b5.g(question.a().c), TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()));
        this.b.c(dBAnswer);
        return dBAnswer;
    }

    public final List c(DBAnswer answer, StudiableQuestion question, long j) throws Exception {
        a aVar;
        List listB;
        Intrinsics.checkNotNullParameter(answer, "answer");
        Intrinsics.checkNotNullParameter(question, "question");
        if (!(question instanceof RevealSelfAssessmentStudiableQuestion) && !(question instanceof MultipleChoiceStudiableQuestion)) {
            if (question instanceof WrittenStudiableQuestion) {
                WrittenStudiableQuestion writtenStudiableQuestion = (WrittenStudiableQuestion) question;
                if (writtenStudiableQuestion.c.b()) {
                    long id = answer.getId();
                    O0 o0 = O0.PROMPT;
                    StudiableQuestionMetadata studiableQuestionMetadata = writtenStudiableQuestion.c;
                    listB = B.j(d(id, o0, AbstractC3106b5.g(studiableQuestionMetadata.c), Long.valueOf(studiableQuestionMetadata.b), j), d(answer.getId(), O0.ANSWER, AbstractC3106b5.g(studiableQuestionMetadata.d), null, j));
                } else {
                    listB = K.a;
                }
            } else {
                listB = K.a;
            }
            aVar = this;
        } else if (question.a().b()) {
            aVar = this;
            listB = A.b(aVar.d(answer.getId(), O0.ANSWER, AbstractC3106b5.g(question.a().d), Long.valueOf(question.a().b), j));
        } else {
            aVar = this;
            listB = K.a;
        }
        if (!listB.isEmpty()) {
            A1 a1 = aVar.d;
            if (a1 == null) {
                throw new IllegalStateException("studyModeType should never be empty");
            }
            if (a1 == A1.LEARNING_ASSISTANT && !listB.isEmpty()) {
                aVar.b.a(listB, null);
                return listB;
            }
        }
        return listB;
    }

    public final DBQuestionAttribute d(long j, O0 o0, O1 o1, Long l, long j2) {
        DBQuestionAttribute dBQuestionAttribute = new DBQuestionAttribute();
        dBQuestionAttribute.setAnswerId(j);
        dBQuestionAttribute.setPersonId(this.a.getPersonId());
        dBQuestionAttribute.setQuestionSide(o0.a());
        dBQuestionAttribute.setSetId(j2);
        dBQuestionAttribute.setTermId(l);
        dBQuestionAttribute.setTermSide(o1.a());
        dBQuestionAttribute.setTimestamp(TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()));
        return dBQuestionAttribute;
    }
}
