package com.quizlet.features.match.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class Y extends Z {
    public final com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l a;

    public Y(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.l onCloseCallback) {
        Intrinsics.checkNotNullParameter(onCloseCallback, "onCloseCallback");
        this.a = onCloseCallback;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof Y) && this.a.equals(((Y) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Visible(onCloseCallback=" + this.a + ")";
    }
}
