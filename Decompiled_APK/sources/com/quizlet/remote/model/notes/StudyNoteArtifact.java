package com.quizlet.remote.model.notes;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class StudyNoteArtifact {
    public final List a;

    public StudyNoteArtifact(@InterfaceC4853h(name = "studyNotesArtifacts") @NotNull List<MagicNotesArtifactResponse> artifact) {
        Intrinsics.checkNotNullParameter(artifact, "artifact");
        this.a = artifact;
    }

    public StudyNoteArtifact(List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list);
    }
}
