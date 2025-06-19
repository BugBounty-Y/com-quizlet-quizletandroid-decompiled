package com.quizlet.learn.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLog;
import com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLogger;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.G1;
import com.quizlet.learn.data.onboarding.C4551a;
import com.quizlet.learn.data.onboarding.C4552b;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class i extends w0 {
    public final com.quizlet.data.repository.course.membership.c b;
    public final LearnOnboardingEventLogger c;
    public com.quizlet.features.infra.studysetting.managers.a d;
    public final int e;
    public final long f;
    public final G1 g;
    public final String h;
    public final long i;
    public final boolean j;
    public final InterfaceC4176w0 k;
    public boolean l;
    public final s0 m;
    public final d0 n;

    public i(m0 savedStateHandle, com.quizlet.data.repository.course.membership.c presentationUseCase, LearnOnboardingEventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(presentationUseCase, "presentationUseCase");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = presentationUseCase;
        this.c = eventLogger;
        Object objA = savedStateHandle.a("navigationSource");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.e = ((Number) objA).intValue();
        Object objA2 = savedStateHandle.a("studyableModelData");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        StudyableModelData studyableModelData = (StudyableModelData) objA2;
        this.f = studyableModelData.k();
        this.g = studyableModelData.getStudyableType();
        Object objA3 = savedStateHandle.a("studyableModelTitle");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.h = (String) objA3;
        Object objA4 = savedStateHandle.a("studyableModelLocalId");
        if (objA4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.i = ((Number) objA4).longValue();
        Object objA5 = savedStateHandle.a("selectedOnlyIntent");
        if (objA5 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.j = ((Boolean) objA5).booleanValue();
        Object objA6 = savedStateHandle.a("meteredEvent");
        if (objA6 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.k = (InterfaceC4176w0) objA6;
        this.m = e0.c(C4552b.a);
        this.n = e0.b(0, 0, null, 7);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4559f(this, null), 3);
    }

    public static ArrayList A(com.quizlet.learn.data.onboarding.d dVar) {
        kotlinx.collections.immutable.e eVar;
        if (dVar instanceof C4551a) {
            kotlinx.collections.immutable.e eVar2 = ((C4551a) dVar).a;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(eVar2, 10));
            Iterator<E> it2 = eVar2.iterator();
            while (it2.hasNext()) {
                arrayList.add(((com.quizlet.learn.data.onboarding.m) it2.next()).a);
            }
            return arrayList;
        }
        if (!(dVar instanceof com.quizlet.learn.data.onboarding.c)) {
            if (dVar instanceof C4552b) {
                throw new IllegalStateException("Should not be loading");
            }
            throw new NoWhenBranchMatchedException();
        }
        com.quizlet.learn.data.onboarding.n nVar = ((com.quizlet.learn.data.onboarding.c) dVar).b;
        if (nVar == null || (eVar = nVar.a) == null) {
            return null;
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(eVar, 10));
        Iterator<E> it3 = eVar.iterator();
        while (it3.hasNext()) {
            arrayList2.add(((com.quizlet.learn.data.onboarding.m) it3.next()).a);
        }
        return arrayList2;
    }

    public final void B(com.quizlet.learn.data.onboarding.i event) {
        assistantMode.enums.y yVar;
        com.quizlet.learn.data.onboarding.t tVar;
        com.quizlet.studiablemodels.assistantMode.a aVar;
        com.quizlet.learn.data.onboarding.k kVar;
        com.quizlet.studiablemodels.assistantMode.a aVar2;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean z = event instanceof com.quizlet.learn.data.onboarding.f;
        long j = this.f;
        LearnOnboardingEventLogger learnOnboardingEventLogger = this.c;
        if (z) {
            com.quizlet.learn.data.onboarding.f fVar = (com.quizlet.learn.data.onboarding.f) event;
            com.quizlet.studiablemodels.assistantMode.a aVar3 = fVar.a;
            learnOnboardingEventLogger.getClass();
            LearnOnboardingEventLog.Companion companion = LearnOnboardingEventLog.b;
            com.quizlet.eventlogger.features.learnonboarding.a aVar4 = new com.quizlet.eventlogger.features.learnonboarding.a(aVar3, j, fVar.b, 0);
            companion.getClass();
            learnOnboardingEventLogger.a(LearnOnboardingEventLog.Companion.a("study_paths_intake_screen_click", aVar4));
            return;
        }
        boolean z2 = event instanceof com.quizlet.learn.data.onboarding.h;
        s0 s0Var = this.m;
        if (z2) {
            com.quizlet.learn.data.onboarding.h hVar = (com.quizlet.learn.data.onboarding.h) event;
            assistantMode.enums.y yVar2 = hVar.b;
            ArrayList arrayListA = A((com.quizlet.learn.data.onboarding.d) s0Var.getValue());
            learnOnboardingEventLogger.getClass();
            String strS = arrayListA != null ? CollectionsKt.S(arrayListA, null, null, null, new Z(14), 31) : null;
            LearnOnboardingEventLog.Companion companion2 = LearnOnboardingEventLog.b;
            long j2 = this.f;
            com.quizlet.studiablemodels.assistantMode.a aVar5 = hVar.a;
            com.quizlet.eventlogger.features.learnonboarding.b bVar = new com.quizlet.eventlogger.features.learnonboarding.b(j2, strS, aVar5, yVar2);
            companion2.getClass();
            learnOnboardingEventLogger.a(LearnOnboardingEventLog.Companion.a("study_paths_intake_screen_cta_click", bVar));
            kotlinx.coroutines.E.A(p0.j(this), null, null, new C4560g(this, yVar2, aVar5, com.quizlet.learn.data.onboarding.z.a, null), 3);
            return;
        }
        if (!(event instanceof com.quizlet.learn.data.onboarding.g)) {
            if (!(event instanceof com.quizlet.learn.data.onboarding.e)) {
                throw new NoWhenBranchMatchedException();
            }
            kotlinx.coroutines.E.A(p0.j(this), null, null, new C4558e(this, null), 3);
            return;
        }
        learnOnboardingEventLogger.getClass();
        LearnOnboardingEventLog.Companion companion3 = LearnOnboardingEventLog.b;
        com.braze.requests.framework.m mVar = new com.braze.requests.framework.m(2, j);
        companion3.getClass();
        learnOnboardingEventLogger.a(LearnOnboardingEventLog.Companion.a("study_path_goal_intake_skipped_personalization", mVar));
        com.quizlet.learn.data.onboarding.d dVar = (com.quizlet.learn.data.onboarding.d) s0Var.getValue();
        if (dVar instanceof C4551a) {
            yVar = ((C4551a) dVar).c.a;
        } else {
            if (!(dVar instanceof com.quizlet.learn.data.onboarding.c)) {
                if (!(dVar instanceof C4552b)) {
                    throw new NoWhenBranchMatchedException();
                }
                throw new IllegalStateException("Should not be loading");
            }
            com.quizlet.learn.data.onboarding.v vVar = ((com.quizlet.learn.data.onboarding.c) dVar).c;
            yVar = (vVar == null || (tVar = vVar.b) == null) ? null : tVar.a;
        }
        com.quizlet.learn.data.onboarding.d dVar2 = (com.quizlet.learn.data.onboarding.d) s0Var.getValue();
        if (dVar2 instanceof C4551a) {
            aVar2 = ((C4551a) dVar2).b.a;
        } else {
            if (!(dVar2 instanceof com.quizlet.learn.data.onboarding.c)) {
                if (!(dVar2 instanceof C4552b)) {
                    throw new NoWhenBranchMatchedException();
                }
                throw new IllegalStateException("Should not be loading");
            }
            com.quizlet.learn.data.onboarding.n nVar = ((com.quizlet.learn.data.onboarding.c) dVar2).b;
            if (nVar == null || (kVar = nVar.b) == null) {
                aVar = null;
                kotlinx.coroutines.E.A(p0.j(this), null, null, new C4560g(this, yVar, aVar, com.quizlet.learn.data.onboarding.w.a, null), 3);
            }
            aVar2 = kVar.a;
        }
        aVar = aVar2;
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4560g(this, yVar, aVar, com.quizlet.learn.data.onboarding.w.a, null), 3);
    }
}
