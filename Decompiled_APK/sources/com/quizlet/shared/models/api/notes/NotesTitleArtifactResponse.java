package com.quizlet.shared.models.api.notes;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class NotesTitleArtifactResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return NotesTitleArtifactResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ NotesTitleArtifactResponse(int i, String str) {
        if (1 == (i & 1)) {
            this.a = str;
        } else {
            AbstractC5047c0.k(i, 1, NotesTitleArtifactResponse$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof NotesTitleArtifactResponse) && Intrinsics.b(this.a, ((NotesTitleArtifactResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("NotesTitleArtifactResponse(title="), this.a, ")");
    }
}
