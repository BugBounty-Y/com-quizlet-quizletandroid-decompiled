package com.quizlet.features.practicetest.results.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.google.firebase.crashlytics.internal.common.j;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLogger;
import com.quizlet.features.practicetest.results.data.i;
import com.quizlet.features.practicetest.results.data.k;
import com.quizlet.features.practicetest.results.data.l;
import com.quizlet.features.practicetest.results.data.m;
import com.quizlet.features.practicetest.results.data.n;
import com.quizlet.features.practicetest.results.data.o;
import com.quizlet.features.practicetest.results.data.p;
import com.quizlet.features.practicetest.results.data.v;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class h extends w0 implements a {
    public final m0 b;
    public final q c;
    public final com.quizlet.data.repository.folderwithcreator.e d;
    public final com.google.mlkit.vision.documentscanner.internal.c e;
    public final j f;
    public final com.quizlet.data.interactor.course.a g;
    public final com.google.firebase.perf.logging.b h;
    public final PracticeTestEventLogger i;
    public final String j;
    public final String k;
    public final d0 l;
    public final s0 m;
    public final C4203d n;

    public h(m0 savedStateHandle, q getPracticeTestResultUseCase, com.quizlet.data.repository.folderwithcreator.e practiceTestResultsUiUseCase, com.google.mlkit.vision.documentscanner.internal.c copyPracticeTestUseCase, j updateGradedAnswerUseCase, com.quizlet.data.interactor.course.a createPracticeTestUseCase, com.google.firebase.perf.logging.b getQuestionFormatFromConfigurationUseCase, PracticeTestEventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(getPracticeTestResultUseCase, "getPracticeTestResultUseCase");
        Intrinsics.checkNotNullParameter(practiceTestResultsUiUseCase, "practiceTestResultsUiUseCase");
        Intrinsics.checkNotNullParameter(copyPracticeTestUseCase, "copyPracticeTestUseCase");
        Intrinsics.checkNotNullParameter(updateGradedAnswerUseCase, "updateGradedAnswerUseCase");
        Intrinsics.checkNotNullParameter(createPracticeTestUseCase, "createPracticeTestUseCase");
        Intrinsics.checkNotNullParameter(getQuestionFormatFromConfigurationUseCase, "getQuestionFormatFromConfigurationUseCase");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = savedStateHandle;
        this.c = getPracticeTestResultUseCase;
        this.d = practiceTestResultsUiUseCase;
        this.e = copyPracticeTestUseCase;
        this.f = updateGradedAnswerUseCase;
        this.g = createPracticeTestUseCase;
        this.h = getQuestionFormatFromConfigurationUseCase;
        this.i = eventLogger;
        Object objA = savedStateHandle.a("practiceTestId");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.j = (String) objA;
        Object objA2 = savedStateHandle.a("practiceTestSessionId");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.k = (String) objA2;
        this.l = e0.b(0, 1, null, 5);
        this.m = e0.c(v.a);
        this.n = new C4203d(this);
        B();
    }

    public final String A() {
        Object objA = this.b.a("questionBankId");
        if (objA != null) {
            return (String) objA;
        }
        throw new IllegalArgumentException("Required value was null.");
    }

    public final void B() {
        E.A(p0.j(this), this.n, null, new c(this, null), 2);
    }

    public final void C(n event) {
        Intrinsics.checkNotNullParameter(event, "event");
        boolean zB = Intrinsics.b(event, com.quizlet.features.practicetest.results.data.f.a);
        String practiceTestSessionId = this.k;
        d0 d0Var = this.l;
        if (zB) {
            v vVar = v.a;
            s0 s0Var = this.m;
            s0Var.getClass();
            s0Var.m(null, vVar);
            d0Var.h(new o(A(), practiceTestSessionId));
            return;
        }
        boolean zB2 = Intrinsics.b(event, l.a);
        C4203d c4203d = this.n;
        if (zB2) {
            E.A(p0.j(this), c4203d, null, new b(this, null), 2);
            return;
        }
        if (Intrinsics.b(event, i.a)) {
            B();
            return;
        }
        boolean z = event instanceof com.quizlet.features.practicetest.results.data.j;
        m0 m0Var = this.b;
        if (z) {
            com.quizlet.features.practicetest.results.data.j jVar = (com.quizlet.features.practicetest.results.data.j) event;
            int i = jVar.a;
            String str = jVar.b;
            m0Var.c(str, "questionId");
            d0Var.h(new com.quizlet.features.practicetest.results.data.q(i, str));
            return;
        }
        if (event instanceof k) {
            if (com.quizlet.features.practicetest.common.data.k.a.contains(((k) event).a)) {
                Object objA = m0Var.a("questionId");
                if (objA == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                E.A(p0.j(this), null, null, new g(this, (String) objA, null), 3);
                return;
            }
            return;
        }
        if (event instanceof m) {
            m mVar = (m) event;
            E.A(p0.j(this), c4203d, null, new d(mVar.a, mVar.b, mVar.c, this, null), 2);
            return;
        }
        if (!(event instanceof com.quizlet.features.practicetest.results.data.h)) {
            if (!Intrinsics.b(event, com.quizlet.features.practicetest.results.data.g.a)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.infra.models.upgrade.a navigationSource = com.quizlet.features.infra.models.upgrade.a.x;
            Intrinsics.checkNotNullParameter("create_practice_test", "upgradeSource");
            Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
            d0Var.h(new p());
            return;
        }
        boolean z2 = ((com.quizlet.features.practicetest.results.data.h) event).a;
        String questionBankId = A();
        PracticeTestEventLogger practiceTestEventLogger = this.i;
        practiceTestEventLogger.getClass();
        Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
        String practiceTestInstanceId = this.j;
        Intrinsics.checkNotNullParameter(practiceTestInstanceId, "practiceTestInstanceId");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        PracticeTestEventLog.Companion companion = PracticeTestEventLog.b;
        com.braze.ui.g gVar = new com.braze.ui.g(practiceTestSessionId, practiceTestInstanceId, questionBankId, z2);
        companion.getClass();
        practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("results_page_question_list_clicked", gVar));
    }
}
