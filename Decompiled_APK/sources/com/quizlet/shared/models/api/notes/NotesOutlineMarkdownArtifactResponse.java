package com.quizlet.shared.models.api.notes;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class NotesOutlineMarkdownArtifactResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return NotesOutlineMarkdownArtifactResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ NotesOutlineMarkdownArtifactResponse(int i, String str) {
        if (1 == (i & 1)) {
            this.a = str;
        } else {
            AbstractC5047c0.k(i, 1, NotesOutlineMarkdownArtifactResponse$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof NotesOutlineMarkdownArtifactResponse) && Intrinsics.b(this.a, ((NotesOutlineMarkdownArtifactResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("NotesOutlineMarkdownArtifactResponse(outlineMarkdown="), this.a, ")");
    }
}
