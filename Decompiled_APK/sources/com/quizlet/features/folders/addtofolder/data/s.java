package com.quizlet.features.folders.addtofolder.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s {
    public final com.quizlet.ui.models.content.listitem.o a;
    public final boolean b;

    public s(com.quizlet.ui.models.content.listitem.o studyMaterial, boolean z) {
        Intrinsics.checkNotNullParameter(studyMaterial, "studyMaterial");
        this.a = studyMaterial;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof s)) {
            return false;
        }
        s sVar = (s) obj;
        return Intrinsics.b(this.a, sVar.a) && this.b == sVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AddToFolderStudyMaterial(studyMaterial=" + this.a + ", isSelected=" + this.b + ")";
    }
}
