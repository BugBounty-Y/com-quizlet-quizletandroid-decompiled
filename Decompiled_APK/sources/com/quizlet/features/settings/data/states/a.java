package com.quizlet.features.settings.data.states;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements d {
    public final com.quizlet.features.settings.data.models.g a;

    public a(com.quizlet.features.settings.data.models.g emailError) {
        Intrinsics.checkNotNullParameter(emailError, "emailError");
        this.a = emailError;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && this.a.equals(((a) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return "Error(emailError=" + this.a + ")";
    }
}
