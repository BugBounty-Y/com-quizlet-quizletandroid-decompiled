package com.quizlet.eventlogger.features.explanations;

import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ExplanationsLogger b;
    public final /* synthetic */ ExplanationsLogger.EventData.Exercise c;

    public /* synthetic */ b(ExplanationsLogger explanationsLogger, ExplanationsLogger.EventData.Exercise exercise, int i) {
        this.a = i;
        this.b = explanationsLogger;
        this.c = exercise;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        ExplanationsLogger explanationsLogger = this.b;
        ExplanationsLogger.EventData.Exercise exercise = this.c;
        ExplanationsEventLog.Payload createEvent = (ExplanationsEventLog.Payload) obj;
        switch (this.a) {
            case 0:
                int i = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, exercise);
                break;
            default:
                int i2 = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, exercise);
                break;
        }
        return Unit.a;
    }
}
