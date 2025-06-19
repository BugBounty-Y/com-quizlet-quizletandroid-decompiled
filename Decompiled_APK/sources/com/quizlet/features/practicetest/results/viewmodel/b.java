package com.quizlet.features.practicetest.results.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C3;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLogger;
import com.quizlet.features.practicetest.results.data.r;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        h hVar = this.k;
        String practiceTestInstanceId = hVar.j;
        if (i == 0) {
            Z.e(obj);
            String strA = hVar.A();
            this.j = 1;
            C3 c3 = (C3) hVar.e.b;
            obj = E.J((AbstractC5040y) c3.b, new com.quizlet.remote.model.practicetests.a(c3, strA, practiceTestInstanceId, null), this);
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
        Intrinsics.checkNotNullParameter(practiceTestInstanceId, "practiceTestInstanceId");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        PracticeTestEventLog.Companion companion = PracticeTestEventLog.b;
        com.quizlet.eventlogger.features.practicetest.d dVar = new com.quizlet.eventlogger.features.practicetest.d(practiceTestSessionId, practiceTestInstanceId, questionBankId, 2);
        companion.getClass();
        practiceTestEventLogger.a(PracticeTestEventLog.Companion.a("results_page_retake_test_button_clicked", dVar));
        hVar.l.h(new r((String) obj, hVar.A(), hVar.k));
        return Unit.a;
    }
}
