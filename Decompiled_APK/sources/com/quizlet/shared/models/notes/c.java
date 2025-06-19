package com.quizlet.shared.models.notes;

import kotlinx.serialization.f;
import org.jetbrains.annotations.NotNull;

@f
/* loaded from: classes3.dex */
public interface c {

    @NotNull
    public static final StudyNotesInfo$Companion Companion = StudyNotesInfo$Companion.a;

    StudyNoteArtifactInfo$OutlineMarkdown a();

    String b();

    StudyNoteArtifactInfo$EssayPrompts c();

    Boolean d();

    StudyNoteArtifactInfo$ReviewSheet e();

    String f();

    String g();

    StudyNoteArtifactInfo$Title getTitle();

    String h();

    StudyNoteArtifactInfo$Flashcards i();
}
