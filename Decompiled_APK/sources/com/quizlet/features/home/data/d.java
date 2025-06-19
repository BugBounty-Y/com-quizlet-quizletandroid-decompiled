package com.quizlet.features.home.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements f {
    public final com.quizlet.ui.models.content.listitem.o a;

    public d(com.quizlet.ui.models.content.listitem.o studyMaterial) {
        Intrinsics.checkNotNullParameter(studyMaterial, "studyMaterial");
        this.a = studyMaterial;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "StudyMaterialItemClicked(studyMaterial=" + this.a + ")";
    }
}
