package com.quizlet.explanations.questiondetail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final boolean a;
    public final String b;

    public a(boolean z, String studyMaterialId) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        this.a = z;
        this.b = studyMaterialId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "CanAddToFolderState(canAddToFolder=" + this.a + ", studyMaterialId=" + this.b + ")";
    }
}
