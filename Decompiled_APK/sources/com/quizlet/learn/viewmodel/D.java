package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.Y;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.StudiableQuestionMetadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ G j;
    public final /* synthetic */ MultipleChoiceStudiableQuestion k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(G g, MultipleChoiceStudiableQuestion multipleChoiceStudiableQuestion, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = g;
        this.k = multipleChoiceStudiableQuestion;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new D(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        G g = this.j;
        Y y = g.L;
        DBSession dBSession = g.j1;
        if (dBSession == null) {
            Intrinsics.m("session");
            throw null;
        }
        long id = dBSession.getId();
        com.quizlet.features.infra.basestudy.manager.f fVar = g.Z;
        long j = fVar.u;
        QuestionSettings questionSettingsI = g.I();
        A1 a1 = fVar.o;
        StudiableQuestionMetadata studiableQuestionMetadata = this.k.f;
        studiableQuestionMetadata.getClass();
        y.j(new com.quizlet.learn.data.q(new ShowQuestion.MultipleChoice(this.k, id, j, questionSettingsI, a1, true, studiableQuestionMetadata.d == assistantMode.enums.m.d, this.l)));
        return Unit.a;
    }
}
