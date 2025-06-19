package com.quizlet.remote.model.notes;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteNotesResponse extends ApiResponse {
    public final StudyNoteModel d;

    public RemoteNotesResponse(StudyNoteModel studyNoteModel) {
        this.d = studyNoteModel;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteNotesResponse) && Intrinsics.b(this.d, ((RemoteNotesResponse) obj).d);
    }

    public final int hashCode() {
        StudyNoteModel studyNoteModel = this.d;
        if (studyNoteModel == null) {
            return 0;
        }
        return studyNoteModel.hashCode();
    }

    public final String toString() {
        return "RemoteNotesResponse(models=" + this.d + ")";
    }

    public /* synthetic */ RemoteNotesResponse(StudyNoteModel studyNoteModel, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : studyNoteModel);
    }
}
