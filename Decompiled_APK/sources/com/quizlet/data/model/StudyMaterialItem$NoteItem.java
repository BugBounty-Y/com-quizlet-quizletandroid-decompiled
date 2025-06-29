package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class StudyMaterialItem$NoteItem implements N1 {
    public final M1 a;
    public final NotesToValueInfo b;

    public StudyMaterialItem$NoteItem(M1 studyMaterial, NotesToValueInfo data) {
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
        if (!(obj instanceof StudyMaterialItem$NoteItem)) {
            return false;
        }
        StudyMaterialItem$NoteItem studyMaterialItem$NoteItem = (StudyMaterialItem$NoteItem) obj;
        return Intrinsics.b(this.a, studyMaterialItem$NoteItem.a) && Intrinsics.b(this.b, studyMaterialItem$NoteItem.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "NoteItem(studyMaterial=" + this.a + ", data=" + this.b + ")";
    }
}
