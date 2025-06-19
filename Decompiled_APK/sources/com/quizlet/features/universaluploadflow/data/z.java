package com.quizlet.features.universaluploadflow.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z implements F {
    public final C4459h a;

    public z(C4459h pasteTextNavigationData) {
        Intrinsics.checkNotNullParameter(pasteTextNavigationData, "pasteTextNavigationData");
        this.a = pasteTextNavigationData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof z) && Intrinsics.b(this.a, ((z) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "PasteText(pasteTextNavigationData=" + this.a + ")";
    }
}
