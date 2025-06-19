package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class K implements T {
    public final com.quizlet.features.infra.folder.study.data.a a;

    public K(com.quizlet.features.infra.folder.study.data.a option) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.a = option;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof K) && Intrinsics.b(this.a, ((K) obj).a);
    }

    public final int hashCode() {
        this.a.getClass();
        return 1310784393;
    }

    public final String toString() {
        return "StudyModeClicked(option=" + this.a + ")";
    }
}
