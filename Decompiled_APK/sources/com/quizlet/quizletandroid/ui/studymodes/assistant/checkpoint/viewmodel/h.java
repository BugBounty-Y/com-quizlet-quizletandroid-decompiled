package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.learn.data.LearnRoundSummaryData;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import com.quizlet.studiablemodels.StudiableMeteringData;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import java.util.ArrayList;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ i j;
    public final /* synthetic */ ArrayList k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(i iVar, ArrayList arrayList, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = iVar;
        this.k = arrayList;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        LearnRoundSummaryData learnRoundSummaryData;
        ArrayList arrayList;
        s0 s0Var;
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n nVar;
        StudiableMeteringData studiableMeteringData;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        i iVar = this.j;
        LearnRoundSummaryData learnRoundSummaryData2 = iVar.k;
        boolean z = learnRoundSummaryData2 instanceof LearnRoundSummaryData.TaskCompletedCheckpointData;
        ArrayList arrayList2 = this.k;
        StudiableMeteringData studiableMeteringData2 = iVar.m;
        s0 s0Var2 = iVar.i;
        LearnRoundSummaryData learnRoundSummaryData3 = iVar.k;
        if (z) {
            if (iVar.l) {
                while (true) {
                    Object value2 = s0Var2.getValue();
                    int i = ((LearnRoundSummaryData.TaskCompletedCheckpointData) learnRoundSummaryData3).f;
                    if (studiableMeteringData2 == null || !studiableMeteringData2.f) {
                        s0 s0Var3 = s0Var2;
                        learnRoundSummaryData = learnRoundSummaryData3;
                        arrayList = arrayList2;
                        int i2 = 0;
                        AssistantCheckpointProgressState assistantCheckpointProgressStateB = learnRoundSummaryData.b();
                        int i3 = studiableMeteringData2 != null ? studiableMeteringData2.d : -1;
                        Object[] args = new Object[0];
                        Intrinsics.checkNotNullParameter(args, "args");
                        com.quizlet.qutils.string.f fVar = new com.quizlet.qutils.string.f(R.string.test_to_learn_learn_ending_title, C4933y.P(args));
                        Object[] args2 = new Object[0];
                        Intrinsics.checkNotNullParameter(args2, "args");
                        StudiableMeteringData studiableMeteringData3 = studiableMeteringData2;
                        com.quizlet.qutils.string.f fVar2 = new com.quizlet.qutils.string.f(R.string.test_to_learn_learn_ending_unmetered_description, C4933y.P(args2));
                        Object[] args3 = new Object[0];
                        Intrinsics.checkNotNullParameter(args3, "args");
                        com.quizlet.qutils.string.f fVar3 = new com.quizlet.qutils.string.f(R.string.set_page_study_all_description, C4933y.P(args3));
                        Object[] args4 = new Object[0];
                        Intrinsics.checkNotNullParameter(args4, "args");
                        com.quizlet.qutils.string.f fVar4 = new com.quizlet.qutils.string.f(R.string.test_next_action_take_new_test_title, C4933y.P(args4));
                        Integer numValueOf = Integer.valueOf(R.drawable.ic_study_learn_white);
                        Integer numValueOf2 = Integer.valueOf(R.drawable.ic_study_test);
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l lVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, iVar, i.class, "onStudyAgainClicked", "onStudyAgainClicked()V", 0, 9);
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l lVar2 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, iVar, i.class, "onTakeATestClicked", "onTakeATestClicked()V", 0, 10);
                        s0Var = s0Var3;
                        com.quizlet.learn.ui.g gVarD = iVar.D();
                        StudiableTaskProgress studiableTaskProgressA = learnRoundSummaryData.a();
                        int i4 = studiableTaskProgressA != null ? studiableTaskProgressA.a : 0;
                        StudiableTaskProgress studiableTaskProgressA2 = learnRoundSummaryData.a();
                        if (studiableTaskProgressA2 != null) {
                            i2 = studiableTaskProgressA2.a;
                        }
                        studiableMeteringData = studiableMeteringData3;
                        nVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n(assistantCheckpointProgressStateB, i3, i, fVar, fVar2, fVar3, fVar4, numValueOf, numValueOf2, lVar, lVar2, arrayList, gVarD, new com.quizlet.learn.checkpoint.data.c(i4, i2), iVar.C());
                    } else {
                        AssistantCheckpointProgressState assistantCheckpointProgressStateB2 = learnRoundSummaryData3.b();
                        Object[] args5 = new Object[0];
                        Intrinsics.checkNotNullParameter(args5, "args");
                        com.quizlet.qutils.string.f fVar5 = new com.quizlet.qutils.string.f(R.string.test_to_learn_learn_ending_title, C4933y.P(args5));
                        Object[] args6 = new Object[0];
                        Intrinsics.checkNotNullParameter(args6, "args");
                        com.quizlet.qutils.string.f fVar6 = new com.quizlet.qutils.string.f(R.string.test_to_learn_learn_ending_metered_description, C4933y.P(args6));
                        Object[] args7 = new Object[0];
                        Intrinsics.checkNotNullParameter(args7, "args");
                        s0 s0Var4 = s0Var2;
                        com.quizlet.qutils.string.f fVar7 = new com.quizlet.qutils.string.f(R.string.test_next_action_flashcards_title, C4933y.P(args7));
                        Object[] args8 = new Object[0];
                        Intrinsics.checkNotNullParameter(args8, "args");
                        LearnRoundSummaryData learnRoundSummaryData4 = learnRoundSummaryData3;
                        com.quizlet.qutils.string.f fVar8 = new com.quizlet.qutils.string.f(R.string.test_next_action_take_new_test_title, C4933y.P(args8));
                        Integer numValueOf3 = Integer.valueOf(R.drawable.ic_study_flashcards_white);
                        Integer numValueOf4 = Integer.valueOf(R.drawable.ic_legacy_locked_pill_yellow);
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l lVar3 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, iVar, i.class, "onReviewFlashcardsClicked", "onReviewFlashcardsClicked()V", 0, 7);
                        int i5 = 0;
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l lVar4 = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l(0, iVar, i.class, "onTakeATestClicked", "onTakeATestClicked()V", 0, 8);
                        s0Var = s0Var4;
                        com.quizlet.learn.ui.g gVarD2 = iVar.D();
                        StudiableTaskProgress studiableTaskProgressA3 = learnRoundSummaryData4.a();
                        int i6 = studiableTaskProgressA3 != null ? studiableTaskProgressA3.a : 0;
                        StudiableTaskProgress studiableTaskProgressA4 = learnRoundSummaryData4.a();
                        if (studiableTaskProgressA4 != null) {
                            i5 = studiableTaskProgressA4.a;
                        }
                        arrayList = arrayList2;
                        studiableMeteringData = studiableMeteringData2;
                        learnRoundSummaryData = learnRoundSummaryData4;
                        nVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n(assistantCheckpointProgressStateB2, studiableMeteringData2.d, i, fVar5, fVar6, fVar7, fVar8, numValueOf3, numValueOf4, lVar3, lVar4, arrayList, gVarD2, new com.quizlet.learn.checkpoint.data.c(i6, i5), iVar.C());
                    }
                    arrayList2 = arrayList;
                    if (s0Var.k(value2, nVar)) {
                        break;
                    }
                    studiableMeteringData2 = studiableMeteringData;
                    s0Var2 = s0Var;
                    learnRoundSummaryData3 = learnRoundSummaryData;
                }
            } else {
                do {
                    value = s0Var2.getValue();
                } while (!s0Var2.k(value, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p(learnRoundSummaryData3.b(), arrayList2, iVar.C(), iVar.D())));
            }
        } else {
            if (!(learnRoundSummaryData2 instanceof LearnRoundSummaryData.RoundCheckpointData)) {
                throw new NoWhenBranchMatchedException();
            }
            while (true) {
                Object value3 = s0Var2.getValue();
                AssistantCheckpointProgressState assistantCheckpointProgressStateB3 = learnRoundSummaryData3.b();
                LearnRoundSummaryData.RoundCheckpointData roundCheckpointData = (LearnRoundSummaryData.RoundCheckpointData) learnRoundSummaryData3;
                ArrayList arrayList3 = arrayList2;
                if (s0Var2.k(value3, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.m(assistantCheckpointProgressStateB3, studiableMeteringData2 != null ? studiableMeteringData2.d : -1, roundCheckpointData.f, roundCheckpointData.h, roundCheckpointData.g, roundCheckpointData.i, roundCheckpointData.j, arrayList2, iVar.D(), new com.quizlet.learn.checkpoint.data.c(roundCheckpointData.f, roundCheckpointData.g), iVar.C()))) {
                    break;
                }
                arrayList2 = arrayList3;
            }
        }
        return Unit.a;
    }
}
