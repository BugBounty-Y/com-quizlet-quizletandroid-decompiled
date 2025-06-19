package com.quizlet.learn.viewmodel;

import com.quizlet.eventlogger.features.learn.LearnEventAction;
import com.quizlet.eventlogger.features.learn.LearnEventLog;
import com.quizlet.learn.data.C4544i;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ G b;
    public final /* synthetic */ String c;

    public /* synthetic */ j(G g, String str, int i) {
        this.a = i;
        this.b = g;
        this.c = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                G g = this.b;
                com.quizlet.learn.logging.a aVar = g.r;
                aVar.getClass();
                String studySessionId = this.c;
                Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
                LearnEventLog.Companion companion = LearnEventLog.b;
                LearnEventAction learnEventAction = LearnEventAction.n;
                companion.getClass();
                aVar.a(LearnEventLog.Companion.b(learnEventAction, studySessionId));
                g.L.j(C4544i.a);
                break;
            default:
                com.quizlet.learn.logging.a aVar2 = this.b.r;
                aVar2.getClass();
                String studySessionId2 = this.c;
                Intrinsics.checkNotNullParameter(studySessionId2, "studySessionId");
                LearnEventLog.Companion companion2 = LearnEventLog.b;
                LearnEventAction learnEventAction2 = LearnEventAction.m;
                companion2.getClass();
                aVar2.a(LearnEventLog.Companion.b(learnEventAction2, studySessionId2));
                break;
        }
        return Unit.a;
    }
}
