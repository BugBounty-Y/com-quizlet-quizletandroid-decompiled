package com.quizlet.shared.models.notes;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.e;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudyNotesInfo$Companion {
    public static final /* synthetic */ StudyNotesInfo$Companion a = new StudyNotesInfo$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new e("StudyNotesInfo", K.a(c.class), new kotlin.reflect.c[]{K.a(FullStudyNotesInfo.class), K.a(NewStudyNotesInfo.class)}, new KSerializer[]{FullStudyNotesInfo$$serializer.INSTANCE, NewStudyNotesInfo$$serializer.INSTANCE}, new Annotation[0]);
    }
}
