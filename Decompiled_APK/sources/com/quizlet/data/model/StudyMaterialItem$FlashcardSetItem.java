package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class StudyMaterialItem$FlashcardSetItem implements N1 {
    public final M1 a;
    public final StudySetWithCreator b;

    public StudyMaterialItem$FlashcardSetItem(M1 studyMaterial, StudySetWithCreator data) {
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
        if (!(obj instanceof StudyMaterialItem$FlashcardSetItem)) {
            return false;
        }
        StudyMaterialItem$FlashcardSetItem studyMaterialItem$FlashcardSetItem = (StudyMaterialItem$FlashcardSetItem) obj;
        return Intrinsics.b(this.a, studyMaterialItem$FlashcardSetItem.a) && Intrinsics.b(this.b, studyMaterialItem$FlashcardSetItem.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "FlashcardSetItem(studyMaterial=" + this.a + ", data=" + this.b + ")";
    }
}
