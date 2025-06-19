package com.quizlet.eventlogger.features.practicetest;

import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ String d;

    public /* synthetic */ d(String str, String str2, String str3, int i) {
        this.a = i;
        this.b = str;
        this.c = str2;
        this.d = str3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        PracticeTestEventLog.Payload createEvent = (PracticeTestEventLog.Payload) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPracticeTestSessionId(this.b);
                createEvent.setPracticeTestInstanceId(this.c);
                createEvent.setQuestionBankId(this.d);
                createEvent.setScreen("test_instance_page");
                break;
            case 1:
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPracticeTestSessionId(this.b);
                createEvent.setPracticeTestInstanceId(this.c);
                createEvent.setQuestionBankId(this.d);
                createEvent.setScreen("results");
                break;
            case 2:
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPracticeTestSessionId(this.b);
                createEvent.setPracticeTestInstanceId(this.c);
                createEvent.setQuestionBankId(this.d);
                createEvent.setScreen("results");
                break;
            case 3:
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPracticeTestSessionId(this.b);
                createEvent.setPracticeTestInstanceId(this.c);
                createEvent.setQuestionBankId(this.d);
                createEvent.setScreen("test_instance_page");
                break;
            case 4:
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPracticeTestSessionId(this.b);
                createEvent.setPracticeTestInstanceId(this.c);
                createEvent.setQuestionBankId(this.d);
                createEvent.setScreen("test_instance_page");
                break;
            default:
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPracticeTestSessionId(this.b);
                createEvent.setPracticeTestInstanceId(this.c);
                createEvent.setQuestionBankId(this.d);
                createEvent.setScreen("test_instance_page");
                break;
        }
        return Unit.a;
    }
}
