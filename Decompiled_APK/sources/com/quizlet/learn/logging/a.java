package com.quizlet.learn.logging;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.learn.LearnEventAction;
import com.quizlet.eventlogger.features.learn.LearnEventLog;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final EventLogger a;

    public a(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public final void a(LearnEventLog learnEventLog) {
        this.a.l(learnEventLog);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void b(long j, String str) {
        LearnEventLog.b.getClass();
        LearnEventLog learnEventLog = new LearnEventLog(null, 1, 0 == true ? 1 : 0);
        learnEventLog.setAction(LearnEventAction.k.getValue());
        learnEventLog.setPayload(new LearnEventLog.LearnPayload.SettingsScreenCLose(Long.valueOf(j), str));
        a(learnEventLog);
    }
}
