package com.quizlet.eventlogger.features.explanations;

import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ ExplanationsLogger c;
    public final /* synthetic */ ExplanationsLogger.EventData d;

    public /* synthetic */ a(int i, ExplanationsLogger.EventData eventData, ExplanationsLogger explanationsLogger, String str) {
        this.a = i;
        this.b = str;
        this.c = explanationsLogger;
        this.d = eventData;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        ExplanationsLogger explanationsLogger = this.c;
        ExplanationsLogger.EventData eventData = this.d;
        String str = this.b;
        ExplanationsEventLog.Payload createEvent = (ExplanationsEventLog.Payload) obj;
        switch (this.a) {
            case 0:
                int i = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setContentUrl(str);
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, eventData);
                break;
            case 1:
                int i2 = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setScreenName(str);
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, eventData);
                break;
            case 2:
                int i3 = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setScreenName(str);
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, eventData);
                break;
            case 3:
                int i4 = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setScreenName(str);
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, eventData);
                break;
            default:
                int i5 = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setContentUrl(str);
                explanationsLogger.getClass();
                ExplanationsLogger.e(createEvent, eventData);
                break;
        }
        return Unit.a;
    }
}
