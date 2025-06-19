package com.quizlet.remote.model.notes;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteStudyNotesArtifactsResponse extends ApiResponse {
    public final StudyNoteArtifact d;

    public RemoteStudyNotesArtifactsResponse(StudyNoteArtifact studyNoteArtifact) {
        this.d = studyNoteArtifact;
    }

    public /* synthetic */ RemoteStudyNotesArtifactsResponse(StudyNoteArtifact studyNoteArtifact, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : studyNoteArtifact);
    }
}
