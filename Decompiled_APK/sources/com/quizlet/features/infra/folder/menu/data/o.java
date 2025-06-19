package com.quizlet.features.infra.folder.menu.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements q {
    public final String a;
    public final com.quizlet.data.interactor.folderstudymaterial.g b;

    public o(String folderName, com.quizlet.data.interactor.folderstudymaterial.g undoAction) {
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        Intrinsics.checkNotNullParameter(undoAction, "undoAction");
        this.a = folderName;
        this.b = undoAction;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return Intrinsics.b(this.a, oVar.a) && Intrinsics.b(this.b, oVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SuccessWithUndo(folderName=" + this.a + ", undoAction=" + this.b + ")";
    }
}
