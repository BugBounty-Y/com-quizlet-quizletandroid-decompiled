package com.quizlet.features.flashcards.engine;

import androidx.glance.appwidget.protobuf.Z;
import assistantMode.enums.EnumC1448b;
import assistantMode.enums.m;
import assistantMode.refactored.types.flashcards.FlashcardAnswer;
import assistantMode.types.QuestionMetadata;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBQuestionAttribute;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.O0;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class e extends i implements Function2 {
    public final /* synthetic */ h j;
    public final /* synthetic */ List k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(h hVar, List list, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.j = hVar;
        this.k = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Exception {
        int i;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        h hVar = this.j;
        DBStudySet dbStudySet = hVar.n.e();
        com.quizlet.features.infra.basestudy.manager.f fVar = hVar.n;
        DBSession dBSession = fVar.x.C;
        Long l = dBSession != null ? new Long(dBSession.getId()) : null;
        if (dbStudySet != null && l != null) {
            com.quizlet.data.interactor.school.b bVar = hVar.c;
            DBSession dBSessionB = fVar.x.C;
            boolean z = (dBSessionB == null || dBSessionB.hasEnded()) ? false : true;
            if (dBSessionB == null || !z) {
                dBSessionB = fVar.b();
            }
            long id = dBSessionB.getId();
            List engineAnswers = this.k;
            Intrinsics.checkNotNullParameter(engineAnswers, "engineAnswers");
            Intrinsics.checkNotNullParameter(dbStudySet, "dbStudySet");
            ArrayList arrayList = new ArrayList();
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(engineAnswers, 10));
            Iterator it2 = engineAnswers.iterator();
            while (it2.hasNext()) {
                FlashcardAnswer flashcardAnswer = (FlashcardAnswer) it2.next();
                Long l2 = flashcardAnswer.b.d.a;
                if (l2 == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                long jLongValue = l2.longValue();
                QuestionMetadata questionMetadata = flashcardAnswer.b.d;
                m mVar = questionMetadata.b;
                if (mVar == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                m mVar2 = questionMetadata.c;
                if (mVar2 == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                EnumC1448b enumC1448b = flashcardAnswer.a.a;
                int iOrdinal = enumC1448b.ordinal();
                if (iOrdinal == 2) {
                    i = 2;
                } else if (iOrdinal == 3) {
                    i = 1;
                } else {
                    if (iOrdinal != 4) {
                        throw new IllegalStateException("Invalid AnswerOption " + enumC1448b);
                    }
                    i = 0;
                }
                ArrayList arrayList3 = arrayList2;
                DBStudySet dBStudySet = dbStudySet;
                Iterator it3 = it2;
                DBAnswer dBAnswer = new DBAnswer(id, dbStudySet.getId(), jLongValue, A1.FLASHCARDS, flashcardAnswer.c, i, ((com.quizlet.infra.legacysyncengine.managers.d) bVar.b).e.getPersonId(), AbstractC3106b5.g(mVar), flashcardAnswer.d);
                if (dBStudySet.getHasDiagrams()) {
                    DBQuestionAttribute dBQuestionAttribute = new DBQuestionAttribute();
                    dBQuestionAttribute.setTermId(Long.valueOf(dBAnswer.getTermId()));
                    dBQuestionAttribute.setSetId(dBAnswer.getSetId());
                    dBQuestionAttribute.setAnswerId(dBAnswer.getId());
                    dBQuestionAttribute.setTermSide(AbstractC3106b5.g(mVar2).a());
                    dBQuestionAttribute.setQuestionSide(O0.ANSWER.a());
                    dBQuestionAttribute.setTimestamp(dBAnswer.getTimestamp());
                    arrayList.add(dBQuestionAttribute);
                }
                arrayList3.add(dBAnswer);
                arrayList2 = arrayList3;
                dbStudySet = dBStudySet;
                it2 = it3;
            }
            com.quizlet.infra.legacysyncengine.managers.i iVar = (com.quizlet.infra.legacysyncengine.managers.i) bVar.c;
            iVar.a(arrayList2, null);
            iVar.a(arrayList, null);
        }
        return Unit.a;
    }
}
