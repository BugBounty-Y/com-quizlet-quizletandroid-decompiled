package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class X implements InterfaceC4289j0 {
    public final String a;

    public X(String updateCourseName) {
        Intrinsics.checkNotNullParameter(updateCourseName, "updateCourseName");
        this.a = updateCourseName;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof X) && Intrinsics.b(this.a, ((X) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("CourseAlreadyInFolderModal(updateCourseName="), this.a, ")");
    }
}
