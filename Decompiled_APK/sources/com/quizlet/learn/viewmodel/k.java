package com.quizlet.learn.viewmodel;

import com.quizlet.eventlogger.features.learn.LearnEventAction;
import com.quizlet.eventlogger.features.learn.LearnEventLog;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ G b;

    public /* synthetic */ k(G g, int i) {
        this.a = i;
        this.b = g;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        s0 s0Var;
        Object value;
        int i;
        int i2;
        StudiableTaskProgress studiableTaskProgressB;
        switch (this.a) {
            case 0:
                G g = this.b;
                com.quizlet.learn.logging.a aVar = g.r;
                String studySessionId = g.Z.t;
                aVar.getClass();
                Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
                LearnEventLog.Companion companion = LearnEventLog.b;
                LearnEventAction learnEventAction = LearnEventAction.o;
                companion.getClass();
                aVar.a(LearnEventLog.Companion.b(learnEventAction, studySessionId));
                break;
            default:
                G g2 = this.b;
                do {
                    s0Var = g2.J;
                    value = s0Var.getValue();
                    com.quizlet.data.repository.progress.b bVar = g2.f;
                    StudiableTaskProgress studiableTaskProgressB2 = bVar.b();
                    i = studiableTaskProgressB2 != null ? studiableTaskProgressB2.a : 0;
                    i2 = g2.s1;
                    studiableTaskProgressB = bVar.b();
                } while (!s0Var.k(value, new com.quizlet.learn.ui.toolbar.g(new com.quizlet.learn.ui.toolbar.c(new com.quizlet.learn.ui.progress.g(i, i2, studiableTaskProgressB != null ? studiableTaskProgressB.b : 0, com.quizlet.learn.ui.progress.i.c, 32)), null)));
        }
        return Unit.a;
    }
}
