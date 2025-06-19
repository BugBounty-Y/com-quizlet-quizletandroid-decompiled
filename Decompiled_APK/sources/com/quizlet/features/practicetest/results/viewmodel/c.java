package com.quizlet.features.practicetest.results.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.m0;
import com.google.android.gms.internal.ads.C3;
import com.quizlet.data.model.Y0;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLogger;
import com.quizlet.features.practicetest.results.data.t;
import com.quizlet.features.practicetest.results.data.v;
import com.quizlet.features.practicetest.results.data.y;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public Y0 j;
    public int k;
    public final /* synthetic */ h l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.l = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object value;
        Y0 y0;
        t tVar;
        s0 s0Var;
        Object value2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        h hVar = this.l;
        if (i == 0) {
            Z.e(obj);
            s0 s0Var2 = hVar.m;
            do {
                value = s0Var2.getValue();
            } while (!s0Var2.k(value, v.a));
            this.k = 1;
            C3 c3 = (C3) hVar.c.b;
            obj = E.J((AbstractC5040y) c3.b, new com.quizlet.remote.model.practicetests.e(c3, hVar.j, null), this);
            if (obj != aVar) {
            }
            return aVar;
        }
        if (i != 1) {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            y0 = this.j;
            Z.e(obj);
            tVar = (t) obj;
            String questionBankId = y0.b;
            hVar.b.c(y0.f, "setId");
            m0 m0Var = hVar.b;
            m0Var.c(questionBankId, "questionBankId");
            m0Var.c(new Integer(y0.d), "round");
            do {
                s0Var = hVar.m;
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, tVar));
            y yVar = tVar.a;
            String results = yVar.c + "/" + yVar.d;
            y yVar2 = tVar.a;
            String practiceTestSessionId = hVar.k;
            PracticeTestEventLogger practiceTestEventLogger = hVar.i;
            practiceTestEventLogger.getClass();
            Intrinsics.checkNotNullParameter(results, "results");
            Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
            String practiceTestInstanceId = hVar.j;
            Intrinsics.checkNotNullParameter(practiceTestInstanceId, "practiceTestInstanceId");
            Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
            PracticeTestEventLog.Companion companion = PracticeTestEventLog.b;
            com.quizlet.eventlogger.features.practicetest.a aVar2 = new com.quizlet.eventlogger.features.practicetest.a(results, yVar2.b, practiceTestSessionId, practiceTestInstanceId, questionBankId);
            companion.getClass();
            practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("results_page_seen", aVar2));
            return Unit.a;
        }
        Z.e(obj);
        Y0 y02 = (Y0) obj;
        com.quizlet.data.repository.folderwithcreator.e eVar = hVar.d;
        this.j = y02;
        this.k = 2;
        Object objL = eVar.l(y02, this);
        if (objL != aVar) {
            y0 = y02;
            obj = objL;
            tVar = (t) obj;
            String questionBankId2 = y0.b;
            hVar.b.c(y0.f, "setId");
            m0 m0Var2 = hVar.b;
            m0Var2.c(questionBankId2, "questionBankId");
            m0Var2.c(new Integer(y0.d), "round");
            do {
                s0Var = hVar.m;
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, tVar));
            y yVar3 = tVar.a;
            String results2 = yVar3.c + "/" + yVar3.d;
            y yVar22 = tVar.a;
            String practiceTestSessionId2 = hVar.k;
            PracticeTestEventLogger practiceTestEventLogger2 = hVar.i;
            practiceTestEventLogger2.getClass();
            Intrinsics.checkNotNullParameter(results2, "results");
            Intrinsics.checkNotNullParameter(practiceTestSessionId2, "practiceTestSessionId");
            String practiceTestInstanceId2 = hVar.j;
            Intrinsics.checkNotNullParameter(practiceTestInstanceId2, "practiceTestInstanceId");
            Intrinsics.checkNotNullParameter(questionBankId2, "questionBankId");
            PracticeTestEventLog.Companion companion2 = PracticeTestEventLog.b;
            com.quizlet.eventlogger.features.practicetest.a aVar22 = new com.quizlet.eventlogger.features.practicetest.a(results2, yVar22.b, practiceTestSessionId2, practiceTestInstanceId2, questionBankId2);
            companion2.getClass();
            practiceTestEventLogger2.a(PracticeTestEventLog.Companion.a("results_page_seen", aVar22));
            return Unit.a;
        }
        return aVar;
    }
}
