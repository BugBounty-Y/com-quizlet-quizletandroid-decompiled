package com.quizlet.eventlogger.features.explanations;

import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ExplanationsLogger b;
    public final /* synthetic */ ExplanationsLogger.EventData c;

    public /* synthetic */ c(ExplanationsLogger explanationsLogger, ExplanationsLogger.EventData eventData, int i) {
        this.a = i;
        this.b = explanationsLogger;
        this.c = eventData;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        ExplanationsLogger explanationsLogger = this.b;
        ExplanationsLogger.EventData eventData = this.c;
        ExplanationsEventLog.Payload createEvent = (ExplanationsEventLog.Payload) obj;
        switch (this.a) {
            case 0:
                int i = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, eventData);
                break;
            default:
                int i2 = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, eventData);
                break;
        }
        return Unit.a;
    }
}
