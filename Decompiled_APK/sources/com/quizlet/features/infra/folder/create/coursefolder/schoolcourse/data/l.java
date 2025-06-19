package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l implements n {
    public final String a;

    public l(String schoolName) {
        Intrinsics.checkNotNullParameter(schoolName, "schoolName");
        this.a = schoolName;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof l) && Intrinsics.b(this.a, ((l) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("OnSchoolInputChanged(schoolName="), this.a, ")");
    }
}
