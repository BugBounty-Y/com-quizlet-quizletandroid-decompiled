package com.quizlet.shared.models.api.notes;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class NotesEssayArtifactResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] b = {new C5048d(NotesEssayArtifactItemResponse$$serializer.INSTANCE, 0)};
    public final List a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return NotesEssayArtifactResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ NotesEssayArtifactResponse(int i, List list) {
        if (1 == (i & 1)) {
            this.a = list;
        } else {
            AbstractC5047c0.k(i, 1, NotesEssayArtifactResponse$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof NotesEssayArtifactResponse) && Intrinsics.b(this.a, ((NotesEssayArtifactResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("NotesEssayArtifactResponse(prompts="), this.a);
    }
}
