package com.quizlet.eventlogger.features.practicetest;

import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ String d;
    public final /* synthetic */ int e;
    public final /* synthetic */ ArrayList f;

    public /* synthetic */ c(int i, int i2, String str, String str2, String str3, ArrayList arrayList) {
        this.a = i2;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = i;
        this.f = arrayList;
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
                createEvent.setAdditionalInfo(new PracticeTestEventLog.AdditionalInfo(new PracticeTestEventLog.Settings(this.e, this.f), null, null, null, null, null, null, null, null, 510, null));
                break;
            default:
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPracticeTestSessionId(this.b);
                createEvent.setQuestionBankId(this.c);
                createEvent.setScreen(this.d);
                createEvent.setAdditionalInfo(new PracticeTestEventLog.AdditionalInfo(new PracticeTestEventLog.Settings(this.e, this.f), null, null, null, null, null, null, null, null, 510, null));
                break;
        }
        return Unit.a;
    }
}
