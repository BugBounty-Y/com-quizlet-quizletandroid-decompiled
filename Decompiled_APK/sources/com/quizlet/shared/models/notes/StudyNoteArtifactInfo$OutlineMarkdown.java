package com.quizlet.shared.models.notes;

import com.quizlet.shared.enums.studynotes.d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class StudyNoteArtifactInfo$OutlineMarkdown extends b {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String c;
    public final d d;
    public final String e;
    public final boolean f;
    public final com.quizlet.shared.enums.studynotes.f g;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudyNoteArtifactInfo$OutlineMarkdown$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudyNoteArtifactInfo$OutlineMarkdown(int i, String str, d dVar, String str2, boolean z, com.quizlet.shared.enums.studynotes.f fVar) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, StudyNoteArtifactInfo$OutlineMarkdown$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.c = str;
        this.d = dVar;
        if ((i & 4) == 0) {
            this.e = null;
        } else {
            this.e = str2;
        }
        if ((i & 8) == 0) {
            this.f = false;
        } else {
            this.f = z;
        }
        if ((i & 16) == 0) {
            this.g = com.quizlet.shared.enums.studynotes.f.d;
        } else {
            this.g = fVar;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyNoteArtifactInfo$OutlineMarkdown)) {
            return false;
        }
        StudyNoteArtifactInfo$OutlineMarkdown studyNoteArtifactInfo$OutlineMarkdown = (StudyNoteArtifactInfo$OutlineMarkdown) obj;
        return Intrinsics.b(this.c, studyNoteArtifactInfo$OutlineMarkdown.c) && this.d == studyNoteArtifactInfo$OutlineMarkdown.d && Intrinsics.b(this.e, studyNoteArtifactInfo$OutlineMarkdown.e) && this.f == studyNoteArtifactInfo$OutlineMarkdown.f;
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + (this.c.hashCode() * 31)) * 31;
        String str = this.e;
        return Boolean.hashCode(this.f) + ((iHashCode + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        return "OutlineMarkdown(uuid=" + this.c + ", status=" + this.d + ", outline=" + this.e + ", editedByCreator=" + this.f + ")";
    }

    public StudyNoteArtifactInfo$OutlineMarkdown(String uuid, d status, String str, boolean z) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(status, "status");
        this.c = uuid;
        this.d = status;
        this.e = str;
        this.f = z;
        this.g = com.quizlet.shared.enums.studynotes.f.d;
    }
}
