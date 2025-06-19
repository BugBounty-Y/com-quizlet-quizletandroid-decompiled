package com.quizlet.library.logging;

import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.LibraryEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ a(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                LibraryEventLog.Payload createEvent = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setQuestionBankId(this.b);
                createEvent.setModelType(29);
                createEvent.setLocation("Library");
                createEvent.setPlacement("practice_tests_tab");
                break;
            case 1:
                LibraryEventLog.Payload createEvent2 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.setMediaExerciseId(this.b);
                createEvent2.setModelType(15);
                createEvent2.setLocation("Library");
                createEvent2.setPlacement("your_solutions_tab");
                break;
            case 2:
                LibraryEventLog.Payload createEvent3 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent3, "$this$createEvent");
                createEvent3.setNoteId(this.b);
                createEvent3.setModelType(20);
                createEvent3.setLocation("Library");
                createEvent3.setPlacement("magic_notes_tab");
                break;
            case 3:
                LibraryEventLog.Payload createEvent4 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent4, "$this$createEvent");
                createEvent4.setIsbn(this.b);
                createEvent4.setModelType(14);
                createEvent4.setLocation("Library");
                createEvent4.setPlacement("your_solutions_tab");
                break;
            case 4:
                LibraryEventLog.Payload createEvent5 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent5, "$this$createEvent");
                createEvent5.setQuestionUuid(this.b);
                createEvent5.setModelType(16);
                createEvent5.setLocation("Library");
                createEvent5.setPlacement("your_solutions_tab");
                break;
            default:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                logAndroidEvent.getPayload().setWidgetUrl(this.b);
                break;
        }
        return Unit.a;
    }
}
