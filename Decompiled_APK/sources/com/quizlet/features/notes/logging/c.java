package com.quizlet.features.notes.logging;

import com.comscore.streaming.EventType;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.LearnPostCompletionEventLog;
import com.quizlet.eventlogger.model.LibraryEventLog;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.eventlogger.model.UniversalUploadFlowEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ c(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                NotesEventLog.Payload createEvent = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setIdentifier(this.b);
                break;
            case 1:
                NotesEventLog.Payload createEvent2 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.setNoteUuid(this.b);
                break;
            case 2:
                NotesEventLog.Payload createEvent3 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent3, "$this$createEvent");
                createEvent3.setNoteUuid(this.b);
                break;
            case 3:
                NotesEventLog.Payload createEvent4 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent4, "$this$createEvent");
                createEvent4.setNoteUuid(this.b);
                break;
            case 4:
                NotesEventLog.Payload createEvent5 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent5, "$this$createEvent");
                createEvent5.setNoteUuid(this.b);
                break;
            case 5:
                NotesEventLog.Payload createEvent6 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent6, "$this$createEvent");
                createEvent6.setNoteUuid(this.b);
                break;
            case 6:
                NotesEventLog.Payload createEvent7 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent7, "$this$createEvent");
                createEvent7.setNoteUuid(this.b);
                break;
            case 7:
                NotesEventLog.Payload createEvent8 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent8, "$this$createEvent");
                createEvent8.setNoteUuid(this.b);
                break;
            case 8:
                NotesEventLog.Payload createEvent9 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent9, "$this$createEvent");
                createEvent9.setNoteUuid(this.b);
                break;
            case 9:
                NotesEventLog.Payload createEvent10 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent10, "$this$createEvent");
                createEvent10.setNoteUuid(this.b);
                break;
            case 10:
                NotesEventLog.Payload createEvent11 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent11, "$this$createEvent");
                createEvent11.setNoteUuid(this.b);
                break;
            case 11:
                NotesEventLog.Payload createEvent12 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent12, "$this$createEvent");
                createEvent12.setNoteUuid(this.b);
                break;
            case 12:
                NotesEventLog.Payload createEvent13 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent13, "$this$createEvent");
                createEvent13.setNoteUuid(this.b);
                break;
            case 13:
                NotesEventLog.Payload createEvent14 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent14, "$this$createEvent");
                createEvent14.setNoteUuid(this.b);
                break;
            case 14:
                NotesEventLog.Payload createEvent15 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent15, "$this$createEvent");
                createEvent15.setNoteUuid(this.b);
                break;
            case 15:
                NotesEventLog.Payload createEvent16 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent16, "$this$createEvent");
                createEvent16.setNoteUuid(this.b);
                break;
            case 16:
                NotesEventLog.Payload createEvent17 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent17, "$this$createEvent");
                createEvent17.setNoteUuid(this.b);
                break;
            case 17:
                NotesEventLog.Payload createEvent18 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent18, "$this$createEvent");
                createEvent18.setNoteUuid(this.b);
                break;
            case 18:
                NotesEventLog.Payload createEvent19 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent19, "$this$createEvent");
                createEvent19.setNoteUuid(this.b);
                break;
            case 19:
                NotesEventLog.Payload createEvent20 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent20, "$this$createEvent");
                createEvent20.setNoteUuid(this.b);
                break;
            case 20:
                NotesEventLog.Payload createEvent21 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent21, "$this$createEvent");
                createEvent21.setNoteUuid(this.b);
                break;
            case 21:
                NotesEventLog.Payload createEvent22 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent22, "$this$createEvent");
                createEvent22.setNoteUuid(this.b);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setUserAction(this.b);
                break;
            case EventType.AUDIO /* 23 */:
                AndroidEventLog logUserActionAndroidEvent2 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent2, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent2.setUserAction(this.b);
                break;
            case EventType.VIDEO /* 24 */:
                AndroidEventLog logUserActionAndroidEvent3 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent3, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent3.setUserAction("subject_tapped");
                logUserActionAndroidEvent3.setMessage(this.b);
                break;
            case EventType.SUBS /* 25 */:
                AndroidEventLog logUserActionAndroidEvent4 = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent4, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent4.setUserAction("subject_category_tapped");
                logUserActionAndroidEvent4.setMessage(this.b);
                break;
            case EventType.CDN /* 26 */:
                UniversalUploadFlowEventLog.Payload createEvent23 = (UniversalUploadFlowEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent23, "$this$createEvent");
                createEvent23.setTabSelected(this.b);
                break;
            case 27:
                UniversalUploadFlowEventLog.Payload createEvent24 = (UniversalUploadFlowEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent24, "$this$createEvent");
                createEvent24.setError(this.b);
                break;
            case 28:
                LearnPostCompletionEventLog.Payload createEvent25 = (LearnPostCompletionEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent25, "$this$createEvent");
                createEvent25.setProgressState(this.b);
                break;
            default:
                LibraryEventLog.Payload createEvent26 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent26, "$this$createEvent");
                createEvent26.setQuery(this.b);
                createEvent26.setLocation("Library");
                break;
        }
        return Unit.a;
    }
}
