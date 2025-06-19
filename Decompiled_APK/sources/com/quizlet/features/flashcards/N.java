package com.quizlet.features.flashcards;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.Y;
import com.quizlet.eventlogger.features.autolaunch.AutoLaunchEventLog;
import com.quizlet.eventlogger.features.autolaunch.AutoLaunchEventLogger;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class N extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ S j;
    public final /* synthetic */ boolean k;
    public final /* synthetic */ int l;
    public final /* synthetic */ int m;
    public final /* synthetic */ int n;
    public final /* synthetic */ int o;
    public final /* synthetic */ boolean p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N(S s, boolean z, int i, int i2, int i3, int i4, boolean z2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = s;
        this.k = z;
        this.l = i;
        this.m = i2;
        this.n = i3;
        this.o = i4;
        this.p = z2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new N(this.j, this.k, this.l, this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((N) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        S s = this.j;
        boolean z = !((assistantMode.refactored.studyEngines.b) s.c.b().c).m.isEmpty();
        boolean z2 = this.k;
        com.quizlet.features.infra.models.flashcards.c flashcardsMode = z2 ? com.quizlet.features.infra.models.flashcards.c.c : com.quizlet.features.infra.models.flashcards.c.d;
        C4242p onContinueClick = new C4242p(0, s, S.class, "onContinueButtonClicked", "onContinueButtonClicked()V", 0, 10);
        C4242p onResetClick = new C4242p(0, s, S.class, "onResetButtonClicked", "onResetButtonClicked()V", 0, 11);
        C4242p onToggleMode = new C4242p(0, s, S.class, "onToggleModeButtonClicked", "onToggleModeButtonClicked()V", 0, 12);
        C4242p onTestModeClick = new C4242p(0, s, S.class, "onTestModeButtonClicked", "onTestModeButtonClicked()V", 0, 13);
        C4242p onLearnModeClick = new C4242p(0, s, S.class, "onLearnButtonClicked", "onLearnButtonClicked()V", 0, 14);
        com.quizlet.explanations.textbook.ui.f onLinearProgressEvent = new com.quizlet.explanations.textbook.ui.f(1, s, S.class, "onLinearProgressEvent", "onLinearProgressEvent(Lcom/quizlet/assembly/compose/buttons/LinearProgressEvent;)V", 0, 8);
        Intrinsics.checkNotNullParameter(flashcardsMode, "flashcardsMode");
        Intrinsics.checkNotNullParameter(onContinueClick, "onContinueClick");
        Intrinsics.checkNotNullParameter(onResetClick, "onResetClick");
        Intrinsics.checkNotNullParameter(onToggleMode, "onToggleMode");
        Intrinsics.checkNotNullParameter(onTestModeClick, "onTestModeClick");
        Intrinsics.checkNotNullParameter(onLearnModeClick, "onLearnModeClick");
        Intrinsics.checkNotNullParameter(onLinearProgressEvent, "onLinearProgressEvent");
        com.quizlet.features.infra.models.flashcards.c cVar = com.quizlet.features.infra.models.flashcards.c.d;
        int i = this.l;
        com.google.android.gms.internal.ads.N uVar = flashcardsMode == cVar ? new com.quizlet.features.flashcards.data.u(z, onLearnModeClick, onResetClick, onLinearProgressEvent) : i == 0 ? new com.quizlet.features.flashcards.data.d(z, onLearnModeClick, onResetClick, onLinearProgressEvent) : new com.quizlet.features.flashcards.data.s(onContinueClick, onLearnModeClick, onResetClick);
        int iA = uVar.a();
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        com.quizlet.qutils.string.f fVar = new com.quizlet.qutils.string.f(iA, C4933y.P(args));
        com.quizlet.qutils.string.g gVarB = uVar.b();
        if (gVarB == null) {
            Intrinsics.checkNotNullParameter("", "string");
            gVarB = new com.quizlet.qutils.string.e("");
        }
        com.quizlet.qutils.string.f fVar2 = new com.quizlet.qutils.string.f(R.string.flashcards_summary_you_learned_swipe, kotlin.collections.B.j(fVar, gVarB));
        if ((uVar instanceof com.quizlet.features.flashcards.data.u) || (uVar instanceof com.quizlet.features.flashcards.data.d)) {
            s.k.getClass();
            s.E = new Long(System.currentTimeMillis());
            boolean z3 = !((assistantMode.refactored.studyEngines.b) s.c.b().c).m.isEmpty();
            AutoLaunchEventLogger autoLaunchEventLogger = s.j;
            autoLaunchEventLogger.getClass();
            AutoLaunchEventLog.Companion companion = AutoLaunchEventLog.b;
            com.quizlet.assembly.compose.modals.g gVar = new com.quizlet.assembly.compose.modals.g(z3, 3);
            companion.getClass();
            autoLaunchEventLogger.a(AutoLaunchEventLog.Companion.a("auto_launch_button_reached", gVar));
        }
        Y y = s.t;
        boolean z4 = i == 0;
        int i2 = this.m;
        ArrayList arrayListK = z2 ? kotlin.collections.B.k(new com.quizlet.assembly.widgets.progress.c(R.string.flashcards_know, i2, com.quizlet.assembly.widgets.progress.e.a), new com.quizlet.assembly.widgets.progress.c(R.string.flashcards_still_learning, i, com.quizlet.assembly.widgets.progress.e.b)) : kotlin.collections.B.k(new com.quizlet.assembly.widgets.progress.c(R.string.flashcards_completed, i2, com.quizlet.assembly.widgets.progress.e.a));
        arrayListK.add(new com.quizlet.assembly.widgets.progress.c(R.string.flashcards_terms_left, (this.n - i2) - i, com.quizlet.assembly.widgets.progress.e.c));
        com.quizlet.assembly.widgets.progress.d dVar = new com.quizlet.assembly.widgets.progress.d(arrayListK);
        int i3 = this.m;
        int i4 = this.o;
        int i5 = this.n;
        y.l(new com.quizlet.features.flashcards.data.q(i5, this.l, i3, i5, i4, z4, this.p, dVar, fVar2, uVar));
        return Unit.a;
    }
}
