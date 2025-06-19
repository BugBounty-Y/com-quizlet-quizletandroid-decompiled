package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4272b implements T {
    public final com.quizlet.ui.models.content.listitem.o a;

    public C4272b(com.quizlet.ui.models.content.listitem.o item) {
        Intrinsics.checkNotNullParameter(item, "item");
        this.a = item;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4272b) && Intrinsics.b(this.a, ((C4272b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "AddRecsToFolderClicked(item=" + this.a + ")";
    }
}
