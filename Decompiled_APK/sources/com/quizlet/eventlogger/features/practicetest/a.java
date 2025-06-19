package com.quizlet.eventlogger.features.practicetest;

import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ String b;
    public final /* synthetic */ int c;
    public final /* synthetic */ String d;
    public final /* synthetic */ String e;
    public final /* synthetic */ String f;

    public /* synthetic */ a(String str, int i, String str2, String str3, String str4) {
        this.b = str;
        this.c = i;
        this.d = str2;
        this.e = str3;
        this.f = str4;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        PracticeTestEventLog.Payload createEvent = (PracticeTestEventLog.Payload) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPracticeTestSessionId(this.b);
                createEvent.setPracticeTestInstanceId(this.d);
                createEvent.setQuestionBankId(this.e);
                createEvent.setScreen("test_instance_page");
                createEvent.setAdditionalInfo(new PracticeTestEventLog.AdditionalInfo(null, null, null, null, this.f, Integer.valueOf(this.c), null, null, null, 463, null));
                break;
            default:
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setAdditionalInfo(new PracticeTestEventLog.AdditionalInfo(null, null, null, null, null, null, this.b, Integer.valueOf(this.c), null, 319, null));
                createEvent.setPracticeTestSessionId(this.d);
                createEvent.setPracticeTestInstanceId(this.e);
                createEvent.setQuestionBankId(this.f);
                createEvent.setScreen("results");
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(String str, String str2, String str3, String str4, int i) {
        this.b = str;
        this.d = str2;
        this.e = str3;
        this.f = str4;
        this.c = i;
    }
}
