package com.quizlet.shared.models.api.notes;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class NotesOutlineArtifactHistoryResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public final boolean a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return NotesOutlineArtifactHistoryResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ NotesOutlineArtifactHistoryResponse(int i, boolean z) {
        if ((i & 1) == 0) {
            this.a = false;
        } else {
            this.a = z;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof NotesOutlineArtifactHistoryResponse) && this.a == ((NotesOutlineArtifactHistoryResponse) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("NotesOutlineArtifactHistoryResponse(userEdited="), this.a);
    }
}
