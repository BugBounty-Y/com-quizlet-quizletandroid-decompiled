package com.quizlet.features.notes.logging;

import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.NotesEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function1 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ String b;
    public final /* synthetic */ boolean c;

    public /* synthetic */ b(String str, boolean z) {
        this.b = str;
        this.c = z;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                NotesEventLog.Payload createEvent = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setVisible(Boolean.valueOf(this.c));
                createEvent.setNoteUuid(this.b);
                break;
            default:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                logAndroidEvent.setAuthenticationProvider(this.b);
                logAndroidEvent.setSignUp(Boolean.valueOf(this.c));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ b(boolean z, String str) {
        this.c = z;
        this.b = str;
    }
}
