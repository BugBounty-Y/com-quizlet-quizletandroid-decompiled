package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4286i implements T {
    public final com.quizlet.features.infra.models.folders.c a;

    public C4286i(com.quizlet.features.infra.models.folders.c subfolderUiData) {
        Intrinsics.checkNotNullParameter(subfolderUiData, "subfolderUiData");
        this.a = subfolderUiData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4286i) && Intrinsics.b(this.a, ((C4286i) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "EditTagClicked(subfolderUiData=" + this.a + ")";
    }
}
