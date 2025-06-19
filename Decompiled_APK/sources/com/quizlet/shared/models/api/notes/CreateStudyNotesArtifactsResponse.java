package com.quizlet.shared.models.api.notes;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class CreateStudyNotesArtifactsResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final String b;
    public final com.quizlet.shared.enums.studynotes.d c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return CreateStudyNotesArtifactsResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ CreateStudyNotesArtifactsResponse(int i, String str, String str2, com.quizlet.shared.enums.studynotes.d dVar) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, CreateStudyNotesArtifactsResponse$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = str2;
        this.c = dVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CreateStudyNotesArtifactsResponse)) {
            return false;
        }
        CreateStudyNotesArtifactsResponse createStudyNotesArtifactsResponse = (CreateStudyNotesArtifactsResponse) obj;
        return Intrinsics.b(this.a, createStudyNotesArtifactsResponse.a) && Intrinsics.b(this.b, createStudyNotesArtifactsResponse.b) && this.c == createStudyNotesArtifactsResponse.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "CreateStudyNotesArtifactsResponse(uuid=" + this.a + ", type=" + this.b + ", status=" + this.c + ")";
    }
}
