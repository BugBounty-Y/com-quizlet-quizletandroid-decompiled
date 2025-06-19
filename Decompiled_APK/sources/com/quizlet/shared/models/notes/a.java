package com.quizlet.shared.models.notes;

import java.lang.annotation.Annotation;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.e;

/* loaded from: classes3.dex */
public final class a extends r implements Function0 {
    public static final a a = new a(0);

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        return new e("StudyNoteArtifactInfo", K.a(b.class), new kotlin.reflect.c[]{K.a(StudyNoteArtifactInfo$EssayPrompts.class), K.a(StudyNoteArtifactInfo$Flashcards.class), K.a(StudyNoteArtifactInfo$OutlineMarkdown.class), K.a(StudyNoteArtifactInfo$ReviewSheet.class), K.a(StudyNoteArtifactInfo$Title.class)}, new KSerializer[]{StudyNoteArtifactInfo$EssayPrompts$$serializer.INSTANCE, StudyNoteArtifactInfo$Flashcards$$serializer.INSTANCE, StudyNoteArtifactInfo$OutlineMarkdown$$serializer.INSTANCE, StudyNoteArtifactInfo$ReviewSheet$$serializer.INSTANCE, StudyNoteArtifactInfo$Title$$serializer.INSTANCE}, new Annotation[0]);
    }
}
