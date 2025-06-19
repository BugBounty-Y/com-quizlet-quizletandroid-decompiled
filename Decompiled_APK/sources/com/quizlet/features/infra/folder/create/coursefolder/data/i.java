package com.quizlet.features.infra.folder.create.coursefolder.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements j {
    public final com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.c a;

    public i(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.c schoolData) {
        Intrinsics.checkNotNullParameter(schoolData, "schoolData");
        this.a = schoolData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && Intrinsics.b(this.a, ((i) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SchoolSelected(schoolData=" + this.a + ")";
    }
}
