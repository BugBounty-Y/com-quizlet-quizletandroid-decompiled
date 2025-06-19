package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.google.android.gms.measurement.internal.J;
import com.quizlet.eventlogger.features.learn.LearnEventAction;
import com.quizlet.eventlogger.features.learn.LearnEventLog;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.L;
import com.quizlet.learn.data.LearnRoundSummaryData;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import java.util.List;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b bVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new u(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        int i = 3;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i iVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i) this.j;
        LearnRoundSummaryData learnRoundSummaryData = iVar.k;
        boolean z = learnRoundSummaryData instanceof LearnRoundSummaryData.TaskCompletedCheckpointData;
        StudyableModelData studyableModelData = iVar.n;
        long jK = studyableModelData.k();
        StudiableTaskProgress studiableTaskProgressA = learnRoundSummaryData.a();
        com.quizlet.learn.logging.a aVar2 = iVar.e;
        aVar2.getClass();
        aVar2.a(LearnEventLog.Companion.c(LearnEventLog.b, LearnEventAction.f, Boolean.valueOf(z), z ? L.TASK_COMPLETION_CHECKPOINT_NON_PLUS : L.TASK_ROUND_CHECKPOINT, jK, studiableTaskProgressA, 8));
        List roundResults = learnRoundSummaryData.c();
        Intrinsics.checkNotNullParameter(roundResults, "roundResults");
        LearnEventAction roundResultsAction = LearnEventAction.e;
        Intrinsics.checkNotNullParameter(roundResultsAction, "roundResultsAction");
        Intrinsics.checkNotNullParameter(roundResults, "roundResults");
        LearnEventLog learnEventLog = new LearnEventLog(null, 1, null);
        learnEventLog.setAction(roundResultsAction.getValue());
        learnEventLog.setPayload(new LearnEventLog.LearnPayload.RoundResults(roundResults));
        aVar2.a(learnEventLog);
        iVar.c.m(studyableModelData.k(), iVar.d.e.getPersonId(), studyableModelData.e());
        Set setIds = studyableModelData.e();
        com.quizlet.remote.model.notes.e eVar = iVar.c;
        eVar.getClass();
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        J j = (J) eVar.c;
        io.reactivex.rxjava3.internal.operators.observable.J jQ = j.d(setIds).q(new com.google.mlkit.vision.documentscanner.internal.c(eVar, 23));
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        io.reactivex.rxjava3.disposables.b bVarU = jQ.u(new com.quizlet.quizletandroid.ui.setpage.terms.c(iVar, i), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        Intrinsics.checkNotNullParameter(bVarU, "<this>");
        iVar.A(bVarU);
        com.quizlet.features.infra.studysetting.datasource.a aVar3 = (com.quizlet.features.infra.studysetting.datasource.a) j.d;
        if (aVar3 != null) {
            aVar3.d();
        }
        com.quizlet.features.infra.studysetting.datasource.a aVar4 = (com.quizlet.features.infra.studysetting.datasource.a) j.e;
        if (aVar4 != null) {
            aVar4.d();
        }
        E.A(p0.j(iVar), null, null, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.f(iVar, null), 3);
        return Unit.a;
    }
}
