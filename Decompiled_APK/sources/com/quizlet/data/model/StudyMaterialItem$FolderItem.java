package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class StudyMaterialItem$FolderItem implements N1 {
    public final M1 a;
    public final CreatedFolderWithCreator b;

    public StudyMaterialItem$FolderItem(M1 studyMaterial, CreatedFolderWithCreator data) {
        Intrinsics.checkNotNullParameter(studyMaterial, "studyMaterial");
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = studyMaterial;
        this.b = data;
    }

    @Override // com.quizlet.data.model.N1
    public final M1 a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyMaterialItem$FolderItem)) {
            return false;
        }
        StudyMaterialItem$FolderItem studyMaterialItem$FolderItem = (StudyMaterialItem$FolderItem) obj;
        return Intrinsics.b(this.a, studyMaterialItem$FolderItem.a) && Intrinsics.b(this.b, studyMaterialItem$FolderItem.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "FolderItem(studyMaterial=" + this.a + ", data=" + this.b + ")";
    }
}
