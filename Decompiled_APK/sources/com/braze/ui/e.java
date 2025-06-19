package com.braze.ui;

import com.quizlet.eventlogger.features.practicetest.PracticeTestEventLog;
import com.quizlet.eventlogger.model.LearnPostCompletionEventLog;
import com.quizlet.eventlogger.model.NotesEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;

    public /* synthetic */ e(int i, String str, String str2) {
        this.a = i;
        this.b = str;
        this.c = str2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                break;
            case 1:
                break;
            case 2:
                break;
            case 3:
                break;
            case 4:
                PracticeTestEventLog.Payload createEvent = (PracticeTestEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPracticeTestSessionId(this.b);
                createEvent.setQuestionBankId(this.c);
                createEvent.setScreen("test_setup_modal");
                break;
            case 5:
                PracticeTestEventLog.Payload createEvent2 = (PracticeTestEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.setPracticeTestSessionId(this.b);
                createEvent2.setQuestionBankId(this.c);
                createEvent2.setScreen("test_landing_page");
                break;
            case 6:
                NotesEventLog.Payload createEvent3 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent3, "$this$createEvent");
                createEvent3.setNoteUuid(this.b);
                createEvent3.setNewTitle(this.c);
                break;
            case 7:
                NotesEventLog.Payload createEvent4 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent4, "$this$createEvent");
                createEvent4.setArtifactName(this.b);
                createEvent4.setNoteUuid(this.c);
                break;
            default:
                LearnPostCompletionEventLog.Payload createEvent5 = (LearnPostCompletionEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent5, "$this$createEvent");
                createEvent5.setClickedButtonName(this.b);
                createEvent5.setProgressState(this.c);
                break;
        }
        return Unit.a;
    }
}
