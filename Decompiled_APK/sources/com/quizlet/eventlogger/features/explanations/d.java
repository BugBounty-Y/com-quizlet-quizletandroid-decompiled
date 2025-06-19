package com.quizlet.eventlogger.features.explanations;

import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ExplanationsLogger b;
    public final /* synthetic */ ExplanationsLogger.EventData.Metering c;
    public final /* synthetic */ ExplanationsLogger.MeteringPlacement d;

    public /* synthetic */ d(ExplanationsLogger explanationsLogger, ExplanationsLogger.EventData.Metering metering2, ExplanationsLogger.MeteringPlacement meteringPlacement, int i) {
        this.a = i;
        this.b = explanationsLogger;
        this.c = metering2;
        this.d = meteringPlacement;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        ExplanationsLogger.MeteringPlacement meteringPlacement = this.d;
        ExplanationsLogger explanationsLogger = this.b;
        ExplanationsLogger.EventData.Metering metering2 = this.c;
        ExplanationsEventLog.Payload createEvent = (ExplanationsEventLog.Payload) obj;
        switch (this.a) {
            case 0:
                int i = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, metering2);
                createEvent.setPlacement(meteringPlacement.getLoggingName());
                break;
            default:
                int i2 = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, metering2);
                createEvent.setPlacement(meteringPlacement.getLoggingName());
                break;
        }
        return Unit.a;
    }
}
