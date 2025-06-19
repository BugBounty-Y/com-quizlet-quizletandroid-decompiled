package com.quizlet.features.folders.data;

import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.o0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4299o0 implements InterfaceC4312v0 {
    public final StudyableModelData.StudyFolder a;
    public final com.quizlet.qutils.string.g b;

    public C4299o0(StudyableModelData.StudyFolder studyableModelData, com.quizlet.qutils.string.g itemTitle) {
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(itemTitle, "itemTitle");
        this.a = studyableModelData;
        this.b = itemTitle;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4299o0)) {
            return false;
        }
        C4299o0 c4299o0 = (C4299o0) obj;
        return this.a.equals(c4299o0.a) && this.b.equals(c4299o0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "GoToLearnMode(studyableModelData=" + this.a + ", itemTitle=" + this.b + ")";
    }
}
