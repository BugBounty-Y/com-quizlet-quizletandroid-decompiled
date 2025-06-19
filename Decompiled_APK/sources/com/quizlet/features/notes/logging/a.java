package com.quizlet.features.notes.logging;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a {
    public static final EnumC4503n b = EnumC4503n.NOTE_IMPORT_EVENTS;
    public static final EnumC4503n c = EnumC4503n.NOTE_ACTIVITY_EVENTS;
    public final EventLogger a;

    public a(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public final void a(NotesEventLog notesEventLog) {
        Intrinsics.checkNotNullParameter(notesEventLog, "<this>");
        this.a.l(notesEventLog);
    }
}
