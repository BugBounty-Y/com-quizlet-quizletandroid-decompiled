package com.quizlet.features.notes.logging;

import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.eventlogger.model.UniversalUploadFlowEventLog;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Integer c;
    public final /* synthetic */ List d;
    public final /* synthetic */ String e;

    public /* synthetic */ e(boolean z, Integer num, List list, String str, int i) {
        this.a = i;
        this.b = z;
        this.c = num;
        this.d = list;
        this.e = str;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                NotesEventLog.Payload createEvent = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setVisible(Boolean.valueOf(this.b));
                Integer num = this.c;
                if (num != null) {
                    createEvent.setCharCount(Integer.valueOf(num.intValue()));
                }
                createEvent.setFileTypes(this.d);
                createEvent.setInputType(this.e);
                break;
            default:
                UniversalUploadFlowEventLog.Payload createEvent2 = (UniversalUploadFlowEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.setVisible(Boolean.valueOf(this.b));
                Integer num2 = this.c;
                if (num2 != null) {
                    createEvent2.setCharCount(Integer.valueOf(num2.intValue()));
                }
                createEvent2.setFileTypes(this.d);
                createEvent2.setInputType(this.e);
                break;
        }
        return Unit.a;
    }
}
