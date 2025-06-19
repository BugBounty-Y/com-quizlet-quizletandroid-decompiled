package com.quizlet.features.practicetest.detail.viewmodel;

import androidx.camera.camera2.internal.c0;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLogger;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.features.practicetest.detail.data.B;
import com.quizlet.features.practicetest.detail.data.C4398a;
import com.quizlet.features.practicetest.detail.data.C4399b;
import com.quizlet.features.practicetest.detail.data.C4400c;
import com.quizlet.features.practicetest.detail.data.C4401d;
import com.quizlet.features.practicetest.detail.data.C4402e;
import com.quizlet.features.practicetest.detail.data.C4403f;
import com.quizlet.features.practicetest.detail.data.C4404g;
import com.quizlet.features.practicetest.detail.data.C4405h;
import com.quizlet.features.practicetest.detail.data.C4406i;
import com.quizlet.features.practicetest.detail.data.F;
import com.quizlet.features.practicetest.detail.data.G;
import com.quizlet.features.practicetest.detail.data.H;
import com.quizlet.features.practicetest.detail.data.j;
import com.quizlet.features.practicetest.detail.data.k;
import com.quizlet.features.practicetest.detail.data.l;
import com.quizlet.features.practicetest.detail.data.m;
import com.quizlet.features.practicetest.detail.data.n;
import com.quizlet.features.practicetest.detail.data.o;
import com.quizlet.features.practicetest.detail.data.p;
import com.quizlet.features.practicetest.detail.data.s;
import com.quizlet.features.practicetest.detail.data.t;
import com.quizlet.features.practicetest.detail.data.u;
import com.quizlet.features.practicetest.detail.data.w;
import com.quizlet.features.practicetest.detail.data.x;
import com.quizlet.features.practicetest.detail.data.z;
import com.quizlet.generated.enums.EnumC4533y0;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class i extends w0 implements a {
    public final m0 b;
    public final com.google.mlkit.common.sdkinternal.b c;
    public final com.quizlet.data.interactor.course.a d;
    public final com.google.firebase.perf.logging.b e;
    public final androidx.work.impl.model.e f;
    public final UserInfoCache g;
    public final PracticeTestEventLogger h;
    public final c0 i;
    public final com.quizlet.data.repository.explanations.myexplanations.a j;
    public final d0 k;
    public final s0 l;
    public final String m;
    public final String n;
    public final h o;
    public final h p;

    public i(m0 savedStateHandle, com.google.mlkit.common.sdkinternal.b shareQuestionBankHelper, com.quizlet.data.interactor.course.a createPracticeTestUseCase, com.google.firebase.perf.logging.b getQuestionFormatFromConfigurationUseCase, androidx.work.impl.model.e practiceTestViewAndTakeEligibilityFeature, UserInfoCache userInfoCache, PracticeTestEventLogger eventLogger, c0 getPracticeTestDetailUiUseCase, com.quizlet.data.repository.explanations.myexplanations.a updateQuestionBankUseCase, com.quizlet.qutils.string.c randomUuidProvider) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(shareQuestionBankHelper, "shareQuestionBankHelper");
        Intrinsics.checkNotNullParameter(createPracticeTestUseCase, "createPracticeTestUseCase");
        Intrinsics.checkNotNullParameter(getQuestionFormatFromConfigurationUseCase, "getQuestionFormatFromConfigurationUseCase");
        Intrinsics.checkNotNullParameter(practiceTestViewAndTakeEligibilityFeature, "practiceTestViewAndTakeEligibilityFeature");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(getPracticeTestDetailUiUseCase, "getPracticeTestDetailUiUseCase");
        Intrinsics.checkNotNullParameter(updateQuestionBankUseCase, "updateQuestionBankUseCase");
        Intrinsics.checkNotNullParameter(randomUuidProvider, "randomUuidProvider");
        this.b = savedStateHandle;
        this.c = shareQuestionBankHelper;
        this.d = createPracticeTestUseCase;
        this.e = getQuestionFormatFromConfigurationUseCase;
        this.f = practiceTestViewAndTakeEligibilityFeature;
        this.g = userInfoCache;
        this.h = eventLogger;
        this.i = getPracticeTestDetailUiUseCase;
        this.j = updateQuestionBankUseCase;
        this.k = e0.b(0, 1, null, 5);
        this.l = e0.c(H.a);
        Object objA = savedStateHandle.a("questionBankUuid");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.m = (String) objA;
        String str = (String) savedStateHandle.a("practiceTestSessionId");
        this.n = str == null ? randomUuidProvider.b() : str;
        this.o = new h(this, 0);
        this.p = new h(this, 1);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.practicetest.detail.viewmodel.i r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7.getClass()
            boolean r0 = r8 instanceof com.quizlet.features.practicetest.detail.viewmodel.c
            if (r0 == 0) goto L16
            r0 = r8
            com.quizlet.features.practicetest.detail.viewmodel.c r0 = (com.quizlet.features.practicetest.detail.viewmodel.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.practicetest.detail.viewmodel.c r0 = new com.quizlet.features.practicetest.detail.viewmodel.c
            r0.<init>(r7, r8)
        L1b:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L37
            if (r2 != r3) goto L2f
            com.quizlet.features.practicetest.detail.viewmodel.i r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
        L2b:
            r6 = r8
            r8 = r7
            r7 = r6
            goto L63
        L2f:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r8)
        L3a:
            kotlinx.coroutines.flow.s0 r8 = r7.l
            java.lang.Object r2 = r8.getValue()
            r4 = r2
            com.quizlet.features.practicetest.detail.data.I r4 = (com.quizlet.features.practicetest.detail.data.I) r4
            com.quizlet.features.practicetest.detail.data.H r4 = com.quizlet.features.practicetest.detail.data.H.a
            boolean r8 = r8.k(r2, r4)
            if (r8 == 0) goto L3a
            r0.j = r7
            r0.m = r3
            androidx.camera.camera2.internal.c0 r8 = r7.i
            r8.getClass()
            com.quizlet.features.practicetest.detail.usecase.d r2 = new com.quizlet.features.practicetest.detail.usecase.d
            r3 = 0
            java.lang.String r4 = r7.m
            r2.<init>(r8, r4, r3)
            java.lang.Object r8 = kotlinx.coroutines.E.m(r2, r0)
            if (r8 != r1) goto L2b
            return r1
        L63:
            com.quizlet.features.practicetest.detail.data.E r7 = (com.quizlet.features.practicetest.detail.data.E) r7
            androidx.lifecycle.m0 r0 = r8.b
            java.lang.Long r1 = r7.b
            java.lang.String r2 = "creator_id"
            r0.c(r1, r2)
            java.lang.String r0 = "question_bank_set_id"
            java.lang.Long r1 = r7.c
            androidx.lifecycle.m0 r2 = r8.b
            r2.c(r1, r0)
            com.quizlet.features.practicetest.detail.data.F r4 = r7.a
            boolean r7 = r4.m
            java.lang.Boolean r7 = java.lang.Boolean.valueOf(r7)
            java.lang.String r0 = "question_bank_private"
            r2.c(r7, r0)
            java.lang.String r7 = "practice_test_configuration"
            com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData r0 = r4.j
            r2.c(r0, r7)
            com.quizlet.eventlogger.features.practicetest.PracticeTestEventLogger r7 = r8.h
            r7.getClass()
            java.lang.String r0 = r8.n
            java.lang.String r1 = "practiceTestSessionId"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.lang.String r1 = "questionBankId"
            java.lang.String r2 = r8.m
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r1)
            com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog$Companion r1 = com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog.b
            com.braze.ui.e r3 = new com.braze.ui.e
            r5 = 5
            r3.<init>(r5, r0, r2)
            r1.getClass()
            java.lang.String r0 = "test_preview_page_seen"
            com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog r0 = com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog.Companion.a(r0, r3)
            r7.a(r0)
        Lb2:
            kotlinx.coroutines.flow.s0 r7 = r8.l
            java.lang.Object r0 = r7.getValue()
            r1 = r0
            com.quizlet.features.practicetest.detail.data.I r1 = (com.quizlet.features.practicetest.detail.data.I) r1
            boolean r7 = r7.k(r0, r4)
            if (r7 == 0) goto Lb2
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.detail.viewmodel.i.A(com.quizlet.features.practicetest.detail.viewmodel.i, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void B() {
        s0 s0Var;
        Object value;
        m0 m0Var = this.b;
        PracticeTestConfigurationData practiceTestConfigurationData = (PracticeTestConfigurationData) m0Var.a("practice_test_configuration");
        if (practiceTestConfigurationData != null) {
            Long l = (Long) m0Var.a("question_bank_set_id");
            E.A(p0.j(this), this.p, null, new b(this, l, practiceTestConfigurationData, null), 2);
            return;
        }
        do {
            s0Var = this.l;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new G(new com.quizlet.features.practicetest.common.data.b(new com.quizlet.featuregate.growthbook.a(this, 10)))));
    }

    public final void C(p event) {
        Intrinsics.checkNotNullParameter(event, "event");
        boolean zB = Intrinsics.b(event, C4398a.a);
        d0 d0Var = this.k;
        if (zB) {
            d0Var.h(t.a);
            return;
        }
        boolean z = event instanceof C4400c;
        m0 m0Var = this.b;
        if (z) {
            Long l = (Long) m0Var.a("creator_id");
            if (l != null) {
                d0Var.h(new B(l.longValue()));
                return;
            }
            return;
        }
        if (Intrinsics.b(event, j.a)) {
            E.A(p0.j(this), null, null, new e(this, null), 3);
            return;
        }
        if (Intrinsics.b(event, C4399b.a)) {
            Object value = this.l.getValue();
            F f = value instanceof F ? (F) value : null;
            if (f != null) {
                Map map = f.i;
                int iO0 = CollectionsKt.o0(map.values());
                int i = f.j.a;
                Set setKeySet = map.keySet();
                ArrayList arrayList = new ArrayList(C.q(setKeySet, 10));
                Iterator it2 = setKeySet.iterator();
                while (it2.hasNext()) {
                    arrayList.add(((EnumC4533y0) it2.next()).a());
                }
                this.h.b(iO0, i, this.n, this.m, "test_landing_page", arrayList);
                return;
            }
            return;
        }
        if (Intrinsics.b(event, l.a)) {
            B();
            return;
        }
        if (event instanceof m) {
            m mVar = (m) event;
            int i2 = mVar.a;
            ArrayList arrayList2 = new ArrayList();
            boolean z2 = mVar.b;
            if (z2) {
                arrayList2.add(EnumC4533y0.MCQ_WITH_SINGLE_ANSWER.a());
            }
            boolean z3 = mVar.c;
            if (z3) {
                arrayList2.add(EnumC4533y0.QUESTION_WITH_SHORT_FREE_RESPONSE.a());
            }
            Unit unit = Unit.a;
            this.h.c(i2, arrayList2, this.n, this.m, "test_landing_page");
            m0Var.c(new PracticeTestConfigurationData(mVar.a, z2, z3), "practice_test_configuration");
            B();
            return;
        }
        if (event instanceof C4403f) {
            d0Var.h(new x(((C4403f) event).a, this.n));
            return;
        }
        if (event instanceof o) {
            d0Var.h(new com.quizlet.features.practicetest.detail.data.C(((o) event).a));
            return;
        }
        if (Intrinsics.b(event, C4404g.a)) {
            E.A(p0.j(this), this.p, null, new f(this, null), 2);
            return;
        }
        boolean zB2 = Intrinsics.b(event, C4401d.a);
        String str = this.m;
        if (zB2) {
            d0Var.h(new s(str));
            return;
        }
        if (Intrinsics.b(event, k.a)) {
            d0Var.h(new z(str));
            return;
        }
        if (event instanceof C4405h) {
            C4405h c4405h = (C4405h) event;
            m0Var.c(new PracticeTestConfigurationData(c4405h.a, c4405h.b, c4405h.c), "practice_test_configuration");
            return;
        }
        if (event instanceof C4406i) {
            E.A(p0.j(this), this.o, null, new d(this, ((C4406i) event).a, null), 2);
        } else if (Intrinsics.b(event, C4402e.a)) {
            d0Var.h(w.a);
        } else {
            if (!(event instanceof n)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.infra.models.upgrade.a navigationSource = com.quizlet.features.infra.models.upgrade.a.x;
            Intrinsics.checkNotNullParameter("create_practice_test", "upgradeSource");
            Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
            d0Var.h(new u());
        }
    }
}
