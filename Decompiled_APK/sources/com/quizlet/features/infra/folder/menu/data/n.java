package com.quizlet.features.infra.folder.menu.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n implements q {
    public final Throwable a;

    public n(Throwable error) {
        Intrinsics.checkNotNullParameter(error, "error");
        this.a = error;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Failure(error=" + this.a + ")";
    }
}
