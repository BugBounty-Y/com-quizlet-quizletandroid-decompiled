package com.quizlet.features.flashcards.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i extends l {
    public final com.quizlet.qutils.string.e a;
    public final com.quizlet.qutils.string.f b;

    public i(com.quizlet.qutils.string.e text, com.quizlet.qutils.string.f title) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(title, "title");
        this.a = text;
        this.b = title;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a.equals(iVar.a) && this.b.equals(iVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.a.hashCode() * 31);
    }

    public final String toString() {
        return "ShowMoreText(text=" + this.a + ", title=" + this.b + ")";
    }
}
