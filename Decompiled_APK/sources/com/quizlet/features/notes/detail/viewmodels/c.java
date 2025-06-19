package com.quizlet.features.notes.detail.viewmodels;

import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.generated.enums.EnumC4465a0;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class c extends w0 implements d {
    public final m0 b;
    public final com.quizlet.data.repository.login.a c;
    public final com.google.firebase.messaging.p d;
    public final com.quizlet.features.notes.logging.f e;
    public final s0 f;
    public final d0 g;
    public final com.quizlet.features.notes.logging.f h;

    public c(m0 stateHandle, com.quizlet.data.repository.login.a getStudyNotesByIdUseCase, com.google.firebase.messaging.p getStudyNotesArtifactUseCase, com.quizlet.features.notes.logging.f notesEventLogger) {
        Intrinsics.checkNotNullParameter(stateHandle, "stateHandle");
        Intrinsics.checkNotNullParameter(getStudyNotesByIdUseCase, "getStudyNotesByIdUseCase");
        Intrinsics.checkNotNullParameter(getStudyNotesArtifactUseCase, "getStudyNotesArtifactUseCase");
        Intrinsics.checkNotNullParameter(notesEventLogger, "notesEventLogger");
        Intrinsics.checkNotNullParameter(stateHandle, "stateHandle");
        Intrinsics.checkNotNullParameter(getStudyNotesByIdUseCase, "getStudyNotesByIdUseCase");
        Intrinsics.checkNotNullParameter(getStudyNotesArtifactUseCase, "getStudyNotesArtifactUseCase");
        Intrinsics.checkNotNullParameter(notesEventLogger, "notesEventLogger");
        this.b = stateHandle;
        this.c = getStudyNotesByIdUseCase;
        this.d = getStudyNotesArtifactUseCase;
        this.e = notesEventLogger;
        this.f = e0.c(com.quizlet.features.notes.detail.states.b.a);
        this.g = e0.b(0, 1, null, 5);
        this.h = notesEventLogger;
    }

    public final String A() {
        Object objA = this.b.a("uuid");
        if (objA != null) {
            return (String) objA;
        }
        throw new IllegalArgumentException("Required value was null.");
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        String strA = A();
        com.quizlet.features.notes.logging.f fVar = this.h;
        fVar.getClass();
        NotesEventLog.Companion companion = NotesEventLog.b;
        String strA2 = EnumC4465a0.ESSAY_PROMPTS_EXITED.a();
        com.quizlet.features.notes.logging.c cVar = new com.quizlet.features.notes.logging.c(strA, 4);
        EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.c;
        companion.getClass();
        fVar.a(NotesEventLog.Companion.a(enumC4503n, strA2, cVar));
    }
}
