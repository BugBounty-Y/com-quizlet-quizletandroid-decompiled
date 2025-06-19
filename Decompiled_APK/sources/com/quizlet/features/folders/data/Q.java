package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class Q implements T {
    public final com.quizlet.data.interactor.folderstudymaterial.g a;

    public Q(com.quizlet.data.interactor.folderstudymaterial.g action) {
        Intrinsics.checkNotNullParameter(action, "action");
        this.a = action;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof Q) && Intrinsics.b(this.a, ((Q) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "UndoDelete(action=" + this.a + ")";
    }
}
