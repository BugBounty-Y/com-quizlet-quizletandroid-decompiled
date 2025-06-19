package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class I implements T {
    public final K0 a;

    public I(K0 sortType) {
        Intrinsics.checkNotNullParameter(sortType, "sortType");
        this.a = sortType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof I) && Intrinsics.b(this.a, ((I) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Sort(sortType=" + this.a + ")";
    }
}
