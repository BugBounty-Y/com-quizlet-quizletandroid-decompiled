package com.quizlet.features.universaluploadflow.flashcards.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final com.quizlet.ui.models.content.listitem.d a;
    public final boolean b;
    public final boolean c;
    public final boolean d;

    public a(com.quizlet.ui.models.content.listitem.d metadata, boolean z, boolean z2, boolean z3) {
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = metadata;
        this.b = z;
        this.c = z2;
        this.d = z3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b && this.c == aVar.c && this.d == aVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.g(d0.g(this.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        return "FlashcardsUploadData(metadata=" + this.a + ", isEligibleForCreation=" + this.b + ", isPrivate=" + this.c + ", isSelected=" + this.d + ")";
    }
}
