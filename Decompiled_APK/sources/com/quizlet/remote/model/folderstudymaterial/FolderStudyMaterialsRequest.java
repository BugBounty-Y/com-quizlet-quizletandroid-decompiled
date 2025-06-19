package com.quizlet.remote.model.folderstudymaterial;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class FolderStudyMaterialsRequest {
    public final long a;
    public final String b;
    public final int c;

    public FolderStudyMaterialsRequest(int i, long j, String studyMaterialId) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        this.a = j;
        this.b = studyMaterialId;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FolderStudyMaterialsRequest)) {
            return false;
        }
        FolderStudyMaterialsRequest folderStudyMaterialsRequest = (FolderStudyMaterialsRequest) obj;
        return this.a == folderStudyMaterialsRequest.a && Intrinsics.b(this.b, folderStudyMaterialsRequest.b) && this.c == folderStudyMaterialsRequest.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.e(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FolderStudyMaterialsRequest(folderId=");
        sb.append(this.a);
        sb.append(", studyMaterialId=");
        sb.append(this.b);
        sb.append(", studyMaterialType=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
