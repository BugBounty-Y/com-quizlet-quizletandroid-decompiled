package com.quizlet.features.settings.data.states;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements l {
    public final com.quizlet.features.settings.data.models.g a;

    public i(com.quizlet.features.settings.data.models.g usernameError) {
        Intrinsics.checkNotNullParameter(usernameError, "usernameError");
        this.a = usernameError;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && this.a.equals(((i) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return "Error(usernameError=" + this.a + ")";
    }
}
