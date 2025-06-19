package com.quizlet.features.practicetest.results.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.m0;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLogger;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.features.practicetest.results.data.r;
import com.quizlet.generated.enums.EnumC4513q0;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ int k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ boolean m;
    public final /* synthetic */ h n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(int i, boolean z, boolean z2, h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = i;
        this.l = z;
        this.m = z2;
        this.n = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        h hVar = this.n;
        if (i == 0) {
            Z.e(obj);
            int i2 = this.k;
            PracticeTestConfigurationData practiceTestConfigurationData = new PracticeTestConfigurationData(i2, this.l, this.m);
            String strA = hVar.A();
            m0 m0Var = hVar.b;
            Object objA = m0Var.a("round");
            if (objA == null) {
                throw new IllegalArgumentException("Required value was null.");
            }
            int iIntValue = ((Number) objA).intValue() + 1;
            EnumC4513q0 enumC4513q0 = EnumC4513q0.TEST_RESULTS_PAGE;
            Long l = (Long) m0Var.a("setId");
            hVar.h.getClass();
            ArrayList arrayListK = com.google.firebase.perf.logging.b.k(practiceTestConfigurationData);
            this.j = 1;
            obj = hVar.g.g(strA, iIntValue, enumC4513q0, l, i2, arrayListK, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        String practiceTestSessionId = hVar.k;
        String questionBankId = hVar.A();
        PracticeTestEventLogger practiceTestEventLogger = hVar.i;
        practiceTestEventLogger.getClass();
        Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
        String practiceTestInstanceId = hVar.j;
        Intrinsics.checkNotNullParameter(practiceTestInstanceId, "practiceTestInstanceId");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        PracticeTestEventLog.Companion companion = PracticeTestEventLog.b;
        com.quizlet.eventlogger.features.practicetest.d dVar = new com.quizlet.eventlogger.features.practicetest.d(practiceTestSessionId, practiceTestInstanceId, questionBankId, 1);
        companion.getClass();
        practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("results_page_new_test_button_clicked", dVar));
        hVar.l.h(new r((String) obj, hVar.A(), hVar.k));
        return Unit.a;
    }
}
