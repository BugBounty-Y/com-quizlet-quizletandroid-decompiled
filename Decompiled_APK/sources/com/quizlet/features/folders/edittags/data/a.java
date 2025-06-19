package com.quizlet.features.folders.edittags.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements f {
    public final long a;
    public final String b;
    public final kotlinx.collections.immutable.e c;

    public a(long j, String label, kotlinx.collections.immutable.e currentTags) {
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(currentTags, "currentTags");
        this.a = j;
        this.b = label;
        this.c = currentTags;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b.equals(aVar.b) && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        return "EditTagModalShown(id=" + this.a + ", label=" + this.b + ", currentTags=" + this.c + ")";
    }
}
