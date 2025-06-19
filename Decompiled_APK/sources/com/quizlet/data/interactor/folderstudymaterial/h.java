package com.quizlet.data.interactor.folderstudymaterial;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h {
    public final g a;

    public h(g undoAction) {
        Intrinsics.checkNotNullParameter(undoAction, "undoAction");
        this.a = undoAction;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && Intrinsics.b(this.a, ((h) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "FolderManipulatedData(undoAction=" + this.a + ")";
    }
}
