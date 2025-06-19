package com.quizlet.eventlogger.features.deeplink;

import com.quizlet.eventlogger.features.deeplink.DeepLinkEventLog;
import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ String d;
    public final /* synthetic */ String e;

    public /* synthetic */ a(String str, String str2, String str3, String str4, int i) {
        this.a = i;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = str4;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String str = this.d;
        String str2 = this.c;
        String str3 = this.b;
        switch (this.a) {
            case 0:
                DeepLinkEventLog.Payload createEvent = (DeepLinkEventLog.Payload) obj;
                int i = DeepLinkEventLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setDeepLinkType(str3);
                createEvent.setUri(str2);
                createEvent.setReferrer(str);
                createEvent.setDeepLinkError(this.e);
                break;
            case 1:
                PracticeTestEventLog.Payload createEvent2 = (PracticeTestEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.setPracticeTestSessionId(str3);
                createEvent2.setPracticeTestInstanceId(str2);
                createEvent2.setQuestionBankId(str);
                createEvent2.setScreen("test_instance_page");
                createEvent2.setAdditionalInfo(new PracticeTestEventLog.AdditionalInfo(null, null, null, null, this.e, null, null, null, null, 495, null));
                break;
            default:
                PracticeTestEventLog.Payload createEvent3 = (PracticeTestEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent3, "$this$createEvent");
                createEvent3.setPracticeTestSessionId(str3);
                createEvent3.setPracticeTestInstanceId(str2);
                createEvent3.setQuestionBankId(str);
                createEvent3.setScreen("test_instance_page");
                createEvent3.setAdditionalInfo(new PracticeTestEventLog.AdditionalInfo(null, null, null, null, this.e, null, null, null, null, 495, null));
                break;
        }
        return Unit.a;
    }
}
