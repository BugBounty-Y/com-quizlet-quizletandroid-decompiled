package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class StudyMaterialItem$TextbookExerciseItem implements N1 {
    public final M1 a;
    public final ExerciseDetails b;

    public StudyMaterialItem$TextbookExerciseItem(M1 studyMaterial, ExerciseDetails data) {
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
        if (!(obj instanceof StudyMaterialItem$TextbookExerciseItem)) {
            return false;
        }
        StudyMaterialItem$TextbookExerciseItem studyMaterialItem$TextbookExerciseItem = (StudyMaterialItem$TextbookExerciseItem) obj;
        return Intrinsics.b(this.a, studyMaterialItem$TextbookExerciseItem.a) && Intrinsics.b(this.b, studyMaterialItem$TextbookExerciseItem.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "TextbookExerciseItem(studyMaterial=" + this.a + ", data=" + this.b + ")";
    }
}
