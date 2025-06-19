package com.quizlet.quizletandroid.ui.library.data;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3698p5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class G extends AbstractC3698p5 {
    public final kotlinx.collections.immutable.b a;
    public final boolean b;

    public G(kotlinx.collections.immutable.b list, boolean z) {
        Intrinsics.checkNotNullParameter(list, "list");
        this.a = list;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof G)) {
            return false;
        }
        G g = (G) obj;
        return Intrinsics.b(this.a, g.a) && this.b == g.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Content(list=" + this.a + ", showEmptyFilter=" + this.b + ")";
    }
}
