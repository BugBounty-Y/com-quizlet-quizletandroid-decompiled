package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import com.quizlet.generated.enums.I1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x extends D {
    public final I1 a;

    public x(I1 subjectCategoryType) {
        Intrinsics.checkNotNullParameter(subjectCategoryType, "subjectCategoryType");
        this.a = subjectCategoryType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof x) {
            return this.a == ((x) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode() * 31;
    }

    public final String toString() {
        return "GoToSubjectCategory(subjectCategoryType=" + this.a + ", subjectType=null)";
    }
}
