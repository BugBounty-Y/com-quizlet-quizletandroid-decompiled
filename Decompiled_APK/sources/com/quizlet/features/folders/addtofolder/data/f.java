package com.quizlet.features.folders.addtofolder.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements n {
    public final com.quizlet.ui.models.content.listitem.o a;
    public final int b;

    public f(com.quizlet.ui.models.content.listitem.o item, int i) {
        Intrinsics.checkNotNullParameter(item, "item");
        this.a = item;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && this.b == fVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "MaterialImpressed(item=" + this.a + ", position=" + this.b + ")";
    }
}
