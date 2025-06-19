package com.quizlet.features.practicetest.takingtest.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.data.model.C4170u0;
import com.quizlet.data.model.U0;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLogger;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.features.practicetest.takingtest.data.C4412f;
import com.quizlet.features.practicetest.takingtest.data.C4414h;
import com.quizlet.features.practicetest.takingtest.data.C4417k;
import com.quizlet.features.practicetest.takingtest.data.C4418l;
import com.quizlet.features.practicetest.takingtest.data.C4419m;
import com.quizlet.features.practicetest.takingtest.data.C4420n;
import com.quizlet.features.practicetest.takingtest.data.F;
import com.quizlet.features.practicetest.takingtest.data.H;
import com.quizlet.features.practicetest.takingtest.data.InterfaceC4410d;
import com.quizlet.features.practicetest.takingtest.data.InterfaceC4415i;
import com.quizlet.features.practicetest.takingtest.data.M;
import com.quizlet.features.practicetest.takingtest.data.N;
import com.quizlet.features.practicetest.takingtest.data.o;
import com.quizlet.features.practicetest.takingtest.data.p;
import com.quizlet.features.practicetest.takingtest.data.q;
import com.quizlet.features.practicetest.takingtest.data.r;
import com.quizlet.features.practicetest.takingtest.data.s;
import com.quizlet.features.practicetest.takingtest.data.t;
import com.quizlet.features.practicetest.takingtest.data.u;
import com.quizlet.features.practicetest.takingtest.data.v;
import com.quizlet.features.practicetest.takingtest.data.w;
import com.quizlet.features.practicetest.takingtest.data.x;
import com.quizlet.features.practicetest.takingtest.data.y;
import com.quizlet.features.practicetest.takingtest.data.z;
import com.quizlet.generated.enums.EnumC4533y0;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class l extends w0 implements a {
    public final m0 b;
    public final com.quizlet.features.practicetest.takingtest.usecase.f c;
    public final androidx.work.impl.model.e d;
    public final PracticeTestEventLogger e;
    public final UserInfoCache f;
    public final com.google.mlkit.vision.documentscanner.internal.c g;
    public final C4203d h;
    public final U0 i;
    public final String j;
    public final s0 k;
    public final d0 l;
    public final d0 m;

    public l(m0 savedStateHandle, com.quizlet.features.practicetest.takingtest.usecase.f questionsUseCase, androidx.work.impl.model.e practiceTestViewAndTakeEligibilityFeature, PracticeTestEventLogger eventLogger, UserInfoCache userInfoCache, com.google.mlkit.vision.documentscanner.internal.c copyPracticeTestUseCase, com.quizlet.qutils.string.c randomUuidProvider) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(questionsUseCase, "questionsUseCase");
        Intrinsics.checkNotNullParameter(practiceTestViewAndTakeEligibilityFeature, "practiceTestViewAndTakeEligibilityFeature");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(copyPracticeTestUseCase, "copyPracticeTestUseCase");
        Intrinsics.checkNotNullParameter(randomUuidProvider, "randomUuidProvider");
        this.b = savedStateHandle;
        this.c = questionsUseCase;
        this.d = practiceTestViewAndTakeEligibilityFeature;
        this.e = eventLogger;
        this.f = userInfoCache;
        this.g = copyPracticeTestUseCase;
        this.h = new C4203d(this);
        C4170u0 c4170u0 = U0.b;
        Object objA = savedStateHandle.a("navigationOrigin");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        String value = (String) objA;
        c4170u0.getClass();
        Intrinsics.checkNotNullParameter(value, "value");
        Iterator it2 = U0.h.iterator();
        while (it2.hasNext()) {
            U0 u0 = (U0) it2.next();
            if (u0.a.equals(value)) {
                this.i = u0;
                String str = (String) this.b.a("practiceTestSessionId");
                this.j = str == null ? randomUuidProvider.b() : str;
                this.k = e0.c(H.a);
                this.l = e0.b(0, 0, null, 7);
                this.m = e0.b(1, 0, null, 6);
                E.A(p0.j(this), null, null, new b(this, null), 3);
                return;
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.practicetest.takingtest.viewmodel.l r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            r9.getClass()
            boolean r0 = r10 instanceof com.quizlet.features.practicetest.takingtest.viewmodel.f
            if (r0 == 0) goto L16
            r0 = r10
            com.quizlet.features.practicetest.takingtest.viewmodel.f r0 = (com.quizlet.features.practicetest.takingtest.viewmodel.f) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            com.quizlet.features.practicetest.takingtest.viewmodel.f r0 = new com.quizlet.features.practicetest.takingtest.viewmodel.f
            r0.<init>(r9, r10)
        L1b:
            java.lang.Object r10 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 0
            r4 = 1
            r5 = 2
            if (r2 == 0) goto L41
            if (r2 == r4) goto L3b
            if (r2 != r5) goto L33
            java.lang.String r9 = r0.k
            com.quizlet.features.practicetest.takingtest.viewmodel.l r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto Lab
        L33:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L3b:
            com.quizlet.features.practicetest.takingtest.viewmodel.l r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L73
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            com.quizlet.db.data.caches.UserInfoCache r10 = r9.f
            boolean r10 = r10.b()
            if (r10 != 0) goto L51
            r9.E()
            goto Lc7
        L51:
            java.lang.String r10 = r9.C()
            java.lang.String r2 = r9.B()
            r0.j = r9
            r0.n = r4
            com.google.mlkit.vision.documentscanner.internal.c r6 = r9.g
            java.lang.Object r6 = r6.b
            com.google.android.gms.internal.ads.C3 r6 = (com.google.android.gms.internal.ads.C3) r6
            com.quizlet.remote.model.practicetests.a r7 = new com.quizlet.remote.model.practicetests.a
            r7.<init>(r6, r10, r2, r3)
            java.lang.Object r10 = r6.b
            kotlinx.coroutines.y r10 = (kotlinx.coroutines.AbstractC5040y) r10
            java.lang.Object r10 = kotlinx.coroutines.E.J(r10, r7, r0)
            if (r10 != r1) goto L73
            goto La6
        L73:
            java.lang.String r10 = (java.lang.String) r10
            com.quizlet.features.practicetest.takingtest.usecase.f r2 = r9.c
            java.lang.String r6 = r9.C()
            r0.j = r9
            r0.k = r10
            r0.n = r5
            r2.getClass()
            int[] r5 = com.quizlet.features.practicetest.takingtest.usecase.a.a
            com.quizlet.data.model.U0 r7 = r9.i
            int r7 = r7.ordinal()
            r5 = r5[r7]
            if (r5 != r4) goto L95
            java.lang.Object r0 = r2.c(r6, r0)
            goto La4
        L95:
            int r4 = r10.length()
            if (r4 != 0) goto La0
            java.lang.Object r0 = r2.c(r6, r0)
            goto La4
        La0:
            java.lang.Object r0 = r2.b(r10, r0)
        La4:
            if (r0 != r1) goto La7
        La6:
            return r1
        La7:
            r8 = r0
            r0 = r9
            r9 = r10
            r10 = r8
        Lab:
            com.quizlet.features.practicetest.takingtest.data.L r10 = (com.quizlet.features.practicetest.takingtest.data.L) r10
            androidx.lifecycle.m0 r1 = r0.b
            java.lang.String r2 = "practiceTestId"
            r1.c(r9, r2)
            com.quizlet.features.practicetest.takingtest.data.J r9 = r10.b
            com.quizlet.features.practicetest.takingtest.data.F r9 = (com.quizlet.features.practicetest.takingtest.data.F) r9
            com.quizlet.features.practicetest.takingtest.data.N r10 = r9.e
            if (r10 == 0) goto Lbf
            r0.D(r10)
        Lbf:
            kotlinx.coroutines.flow.s0 r10 = r0.k
            r10.getClass()
            r10.m(r3, r9)
        Lc7:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.takingtest.viewmodel.l.A(com.quizlet.features.practicetest.takingtest.viewmodel.l, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final String B() {
        String str = (String) this.b.a("practiceTestId");
        return str == null ? "" : str;
    }

    public final String C() {
        String str = (String) this.b.a("questionBankUuid");
        return str == null ? "" : str;
    }

    public final void D(N n) {
        int i = n.a;
        ArrayList arrayList = n.b;
        ArrayList questionFormats = new ArrayList(C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            questionFormats.add(((EnumC4533y0) it2.next()).a());
        }
        String practiceTestInstanceId = B();
        String questionBankId = C();
        PracticeTestEventLogger practiceTestEventLogger = this.e;
        practiceTestEventLogger.getClass();
        Intrinsics.checkNotNullParameter(questionFormats, "questionFormats");
        String practiceTestSessionId = this.j;
        Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
        Intrinsics.checkNotNullParameter(practiceTestInstanceId, "practiceTestInstanceId");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        PracticeTestEventLog.Companion companion = PracticeTestEventLog.b;
        com.quizlet.eventlogger.features.practicetest.c cVar = new com.quizlet.eventlogger.features.practicetest.c(i, 0, practiceTestSessionId, practiceTestInstanceId, questionBankId, questionFormats);
        companion.getClass();
        practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("practice_test_started", cVar));
    }

    public final void E() {
        E.A(p0.j(this), null, null, new j(this, null), 3);
    }

    public final void F(y event) {
        Object value;
        Object value2;
        Object value3;
        Object value4;
        M m;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean z = event instanceof r;
        C4203d c4203d = this.h;
        if (z) {
            E.A(p0.j(this), c4203d, null, new i(this, null), 2);
            return;
        }
        boolean zB = Intrinsics.b(event, C4418l.a);
        s0 s0Var = this.k;
        if (zB) {
            Object value5 = s0Var.getValue();
            F f = value5 instanceof F ? (F) value5 : null;
            if (f == null || (m = f.g) == null) {
                return;
            }
            kotlinx.collections.immutable.g gVar = m.b;
            int iO0 = CollectionsKt.o0(gVar.values());
            PracticeTestConfigurationData practiceTestConfigurationData = m.c;
            Set setKeySet = gVar.keySet();
            ArrayList arrayList = new ArrayList(C.q(setKeySet, 10));
            Iterator it2 = setKeySet.iterator();
            while (it2.hasNext()) {
                arrayList.add(((EnumC4533y0) it2.next()).a());
            }
            this.e.b(iO0, practiceTestConfigurationData.a, this.j, C(), "test_setup_modal", arrayList);
            return;
        }
        if (event instanceof C4420n) {
            G(((C4420n) event).a);
            return;
        }
        if (event instanceof x) {
            G(((x) event).a);
            return;
        }
        boolean zB2 = Intrinsics.b(event, o.a);
        String practiceTestSessionId = this.j;
        com.quizlet.features.practicetest.takingtest.usecase.f fVar = this.c;
        PracticeTestEventLogger practiceTestEventLogger = this.e;
        if (zB2) {
            String practiceTestInstanceId = B();
            String questionBankId = C();
            practiceTestEventLogger.getClass();
            Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
            Intrinsics.checkNotNullParameter(practiceTestInstanceId, "practiceTestInstanceId");
            Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
            PracticeTestEventLog.Companion companion = PracticeTestEventLog.b;
            com.quizlet.eventlogger.features.practicetest.d dVar = new com.quizlet.eventlogger.features.practicetest.d(practiceTestSessionId, practiceTestInstanceId, questionBankId, 5);
            companion.getClass();
            practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("practice_test_next_question_clicked", dVar));
            F f2 = fVar.f();
            do {
                value4 = s0Var.getValue();
            } while (!s0Var.k(value4, f2));
            return;
        }
        if (Intrinsics.b(event, p.a)) {
            String practiceTestInstanceId2 = B();
            String questionBankId2 = C();
            practiceTestEventLogger.getClass();
            Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
            Intrinsics.checkNotNullParameter(practiceTestInstanceId2, "practiceTestInstanceId");
            Intrinsics.checkNotNullParameter(questionBankId2, "questionBankId");
            PracticeTestEventLog.Companion companion2 = PracticeTestEventLog.b;
            com.quizlet.eventlogger.features.practicetest.d dVar2 = new com.quizlet.eventlogger.features.practicetest.d(practiceTestSessionId, practiceTestInstanceId2, questionBankId2, 0);
            companion2.getClass();
            practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("practice_test_previous_question_clicked", dVar2));
            F fG = fVar.g();
            do {
                value3 = s0Var.getValue();
            } while (!s0Var.k(value3, fG));
            return;
        }
        if (event instanceof C4419m) {
            int i = ((C4419m) event).a;
            fVar.f = i;
            ArrayList arrayList2 = fVar.g;
            if (arrayList2 == null) {
                Intrinsics.m("questionsList");
                throw null;
            }
            int size = arrayList2.size();
            ArrayList arrayList3 = fVar.g;
            if (arrayList3 == null) {
                Intrinsics.m("questionsList");
                throw null;
            }
            C4412f c4412f = (C4412f) arrayList3.get(fVar.f);
            kotlinx.collections.immutable.e eVarD = fVar.d();
            InterfaceC4415i[] interfaceC4415iArr = fVar.h;
            if (interfaceC4415iArr == null) {
                Intrinsics.m("currentAnswers");
                throw null;
            }
            F f3 = new F(i, size, c4412f, eVarD, (N) null, interfaceC4415iArr[fVar.f], (M) null, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY);
            String practiceTestInstanceId3 = B();
            String questionBankId3 = C();
            practiceTestEventLogger.getClass();
            String questionId = c4412f.a;
            Intrinsics.checkNotNullParameter(questionId, "questionId");
            String practiceTestSessionId2 = this.j;
            Intrinsics.checkNotNullParameter(practiceTestSessionId2, "practiceTestSessionId");
            Intrinsics.checkNotNullParameter(practiceTestInstanceId3, "practiceTestInstanceId");
            Intrinsics.checkNotNullParameter(questionBankId3, "questionBankId");
            PracticeTestEventLog.Companion companion3 = PracticeTestEventLog.b;
            com.quizlet.eventlogger.features.practicetest.a aVar = new com.quizlet.eventlogger.features.practicetest.a(practiceTestSessionId2, practiceTestInstanceId3, questionBankId3, questionId, i + 1);
            companion3.getClass();
            practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("practice_test_question_list_item_clicked", aVar));
            do {
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, f3));
            return;
        }
        if (Intrinsics.b(event, v.a)) {
            String practiceTestInstanceId4 = B();
            String questionBankId4 = C();
            practiceTestEventLogger.getClass();
            Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
            Intrinsics.checkNotNullParameter(practiceTestInstanceId4, "practiceTestInstanceId");
            Intrinsics.checkNotNullParameter(questionBankId4, "questionBankId");
            PracticeTestEventLog.Companion companion4 = PracticeTestEventLog.b;
            com.quizlet.eventlogger.features.practicetest.d dVar3 = new com.quizlet.eventlogger.features.practicetest.d(practiceTestSessionId, practiceTestInstanceId4, questionBankId4, 4);
            companion4.getClass();
            practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("practice_test_submit_button_pressed", dVar3));
            Object value6 = s0Var.getValue();
            F f4 = value6 instanceof F ? (F) value6 : null;
            E.A(p0.j(this), new d(this, f4), null, new c(f4, this, null), 2);
            return;
        }
        if (Intrinsics.b(event, u.a)) {
            String questionBankId5 = C();
            practiceTestEventLogger.getClass();
            Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
            Intrinsics.checkNotNullParameter(questionBankId5, "questionBankId");
            PracticeTestEventLog.Companion companion5 = PracticeTestEventLog.b;
            com.braze.ui.e eVar = new com.braze.ui.e(4, practiceTestSessionId, questionBankId5);
            companion5.getClass();
            practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("view_question_bank_button_clicked", eVar));
            E();
            return;
        }
        if (event instanceof w) {
            E.A(p0.j(this), c4203d, null, new k(this, (w) event, null), 2);
            return;
        }
        if (event instanceof s) {
            String questionId2 = ((s) event).a;
            String practiceTestInstanceId5 = B();
            String questionBankId6 = C();
            practiceTestEventLogger.getClass();
            Intrinsics.checkNotNullParameter(questionId2, "questionId");
            Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
            Intrinsics.checkNotNullParameter(practiceTestInstanceId5, "practiceTestInstanceId");
            Intrinsics.checkNotNullParameter(questionBankId6, "questionBankId");
            PracticeTestEventLog.Companion companion6 = PracticeTestEventLog.b;
            com.quizlet.eventlogger.features.deeplink.a aVar2 = new com.quizlet.eventlogger.features.deeplink.a(practiceTestSessionId, practiceTestInstanceId5, questionBankId6, questionId2, 2);
            companion6.getClass();
            practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("practice_test_report_question_clicked", aVar2));
            return;
        }
        if (Intrinsics.b(event, q.a)) {
            String practiceTestInstanceId6 = B();
            String questionBankId7 = C();
            practiceTestEventLogger.getClass();
            Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
            Intrinsics.checkNotNullParameter(practiceTestInstanceId6, "practiceTestInstanceId");
            Intrinsics.checkNotNullParameter(questionBankId7, "questionBankId");
            PracticeTestEventLog.Companion companion7 = PracticeTestEventLog.b;
            com.quizlet.eventlogger.features.practicetest.d dVar4 = new com.quizlet.eventlogger.features.practicetest.d(practiceTestSessionId, practiceTestInstanceId6, questionBankId7, 3);
            companion7.getClass();
            practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("practice_test_question_list_clicked", dVar4));
            return;
        }
        if (!(event instanceof t)) {
            if (!Intrinsics.b(event, C4417k.a)) {
                throw new NoWhenBranchMatchedException();
            }
            int length = C().length();
            d0 d0Var = this.m;
            if (length == 0) {
                d0Var.h(new z(false));
                return;
            } else if (this.i == U0.f) {
                E();
                return;
            } else {
                d0Var.h(new z(true));
                return;
            }
        }
        if (com.quizlet.features.practicetest.common.data.k.a.contains(((t) event).a)) {
            fVar.i.add(Integer.valueOf(fVar.f));
            ArrayList arrayList4 = fVar.g;
            if (arrayList4 == null) {
                Intrinsics.m("questionsList");
                throw null;
            }
            int i2 = fVar.f;
            C4412f c4412f2 = (C4412f) arrayList4.get(i2);
            String questionId3 = c4412f2.a;
            Intrinsics.checkNotNullParameter(questionId3, "questionId");
            String question = c4412f2.b;
            Intrinsics.checkNotNullParameter(question, "question");
            List answer = c4412f2.c;
            Intrinsics.checkNotNullParameter(answer, "answer");
            InterfaceC4410d answerOptions = c4412f2.d;
            Intrinsics.checkNotNullParameter(answerOptions, "answerOptions");
            EnumC4533y0 questionFormat = c4412f2.f;
            Intrinsics.checkNotNullParameter(questionFormat, "questionFormat");
            arrayList4.set(i2, new C4412f(questionId3, question, answer, answerOptions, c4412f2.e, questionFormat, c4412f2.g, c4412f2.h, true));
            int i3 = fVar.f;
            ArrayList arrayList5 = fVar.g;
            if (arrayList5 == null) {
                Intrinsics.m("questionsList");
                throw null;
            }
            F f5 = i3 < arrayList5.size() - 1 ? fVar.f() : fVar.g();
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, f5));
        }
    }

    public final void G(InterfaceC4415i submittedAnswer) {
        s0 s0Var;
        Object value;
        com.quizlet.features.practicetest.takingtest.usecase.f fVar = this.c;
        fVar.getClass();
        Intrinsics.checkNotNullParameter(submittedAnswer, "submittedAnswer");
        if ((submittedAnswer instanceof C4414h) && StringsKt.O(((C4414h) submittedAnswer).a)) {
            submittedAnswer = null;
        }
        InterfaceC4415i[] interfaceC4415iArr = fVar.h;
        if (interfaceC4415iArr == null) {
            Intrinsics.m("currentAnswers");
            throw null;
        }
        int i = fVar.f;
        interfaceC4415iArr[i] = submittedAnswer;
        ArrayList arrayList = fVar.g;
        if (arrayList == null) {
            Intrinsics.m("questionsList");
            throw null;
        }
        int size = arrayList.size();
        ArrayList arrayList2 = fVar.g;
        if (arrayList2 == null) {
            Intrinsics.m("questionsList");
            throw null;
        }
        C4412f c4412f = (C4412f) arrayList2.get(fVar.f);
        kotlinx.collections.immutable.e eVarD = fVar.d();
        InterfaceC4415i[] interfaceC4415iArr2 = fVar.h;
        if (interfaceC4415iArr2 == null) {
            Intrinsics.m("currentAnswers");
            throw null;
        }
        F f = new F(i, size, c4412f, eVarD, (N) null, interfaceC4415iArr2[fVar.f], (M) null, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY);
        String practiceTestInstanceId = B();
        String questionBankId = C();
        PracticeTestEventLogger practiceTestEventLogger = this.e;
        practiceTestEventLogger.getClass();
        String questionId = c4412f.a;
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        String practiceTestSessionId = this.j;
        Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
        Intrinsics.checkNotNullParameter(practiceTestInstanceId, "practiceTestInstanceId");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        PracticeTestEventLog.Companion companion = PracticeTestEventLog.b;
        com.quizlet.eventlogger.features.deeplink.a aVar = new com.quizlet.eventlogger.features.deeplink.a(practiceTestSessionId, practiceTestInstanceId, questionBankId, questionId, 1);
        companion.getClass();
        practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("practice_test_answer_changed", aVar));
        do {
            s0Var = this.k;
            value = s0Var.getValue();
        } while (!s0Var.k(value, f));
    }
}
