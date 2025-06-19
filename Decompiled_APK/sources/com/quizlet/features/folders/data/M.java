package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class M implements T {
    public final long a;
    public final com.quizlet.features.infra.models.folders.b b;

    public M(long j, com.quizlet.features.infra.models.folders.b subFolderType) {
        Intrinsics.checkNotNullParameter(subFolderType, "subFolderType");
        this.a = j;
        this.b = subFolderType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof M)) {
            return false;
        }
        M m = (M) obj;
        return this.a == m.a && this.b == m.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "SubFolderTabClicked(id=" + this.a + ", subFolderType=" + this.b + ")";
    }
}
