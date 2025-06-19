package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class N {
    public final String a;

    public N(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof N) {
            return Intrinsics.b(this.a, ((N) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return d0.r(new StringBuilder("VerbatimTtsAnnotation(verbatim="), this.a, ')');
    }
}
