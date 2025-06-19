package com.quizlet.shared.models.api.notes;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class StudyNotesArtifactListRequest {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final boolean b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudyNotesArtifactListRequest$$serializer.INSTANCE;
        }
    }

    public StudyNotesArtifactListRequest(String noteUuid) {
        Intrinsics.checkNotNullParameter(noteUuid, "noteUuid");
        this.a = noteUuid;
        this.b = false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyNotesArtifactListRequest)) {
            return false;
        }
        StudyNotesArtifactListRequest studyNotesArtifactListRequest = (StudyNotesArtifactListRequest) obj;
        return Intrinsics.b(this.a, studyNotesArtifactListRequest.a) && this.b == studyNotesArtifactListRequest.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "StudyNotesArtifactListRequest(noteUuid=" + this.a + ", coreOnly=" + this.b + ")";
    }

    public /* synthetic */ StudyNotesArtifactListRequest(String str, int i, boolean z) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, StudyNotesArtifactListRequest$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = z;
    }
}
