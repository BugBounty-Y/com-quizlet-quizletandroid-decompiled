package com.quizlet.remote.model.notes;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class StudyNotesArtifactRequest {
    public final boolean a;
    public final String b;

    public StudyNotesArtifactRequest(boolean z, String content) {
        Intrinsics.checkNotNullParameter(content, "content");
        this.a = z;
        this.b = content;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyNotesArtifactRequest)) {
            return false;
        }
        StudyNotesArtifactRequest studyNotesArtifactRequest = (StudyNotesArtifactRequest) obj;
        return this.a == studyNotesArtifactRequest.a && Intrinsics.b(this.b, studyNotesArtifactRequest.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "StudyNotesArtifactRequest(aiEdited=" + this.a + ", content=" + this.b + ")";
    }

    public /* synthetic */ StudyNotesArtifactRequest(boolean z, String str, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? false : z, str);
    }
}
