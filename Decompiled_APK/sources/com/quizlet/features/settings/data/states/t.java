package com.quizlet.features.settings.data.states;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements x {
    public final com.quizlet.features.settings.data.models.g a;

    public t(com.quizlet.features.settings.data.models.g error) {
        Intrinsics.checkNotNullParameter(error, "error");
        this.a = error;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof t) && this.a.equals(((t) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return "Error(error=" + this.a + ")";
    }
}
