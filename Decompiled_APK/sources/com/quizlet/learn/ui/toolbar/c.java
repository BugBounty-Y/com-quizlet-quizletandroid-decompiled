package com.quizlet.learn.ui.toolbar;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements d {
    public final com.quizlet.learn.ui.progress.g a;

    public c(com.quizlet.learn.ui.progress.g progressState) {
        Intrinsics.checkNotNullParameter(progressState, "progressState");
        this.a = progressState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && Intrinsics.b(this.a, ((c) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "RedesignedLearnToolbarState(progressState=" + this.a + ")";
    }
}
