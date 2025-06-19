package com.quizlet.shared.models.api.notes;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class NotesEssayArtifactItemResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public final com.quizlet.shared.enums.studynotes.b a;
    public final String b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return NotesEssayArtifactItemResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ NotesEssayArtifactItemResponse(int i, com.quizlet.shared.enums.studynotes.b bVar, String str) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, NotesEssayArtifactItemResponse$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = bVar;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof NotesEssayArtifactItemResponse)) {
            return false;
        }
        NotesEssayArtifactItemResponse notesEssayArtifactItemResponse = (NotesEssayArtifactItemResponse) obj;
        return this.a == notesEssayArtifactItemResponse.a && Intrinsics.b(this.b, notesEssayArtifactItemResponse.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "NotesEssayArtifactItemResponse(difficulty=" + this.a + ", prompt=" + this.b + ")";
    }
}
