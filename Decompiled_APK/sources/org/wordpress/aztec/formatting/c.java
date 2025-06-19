package org.wordpress.aztec.formatting;

import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final int a;
    public final Object b;

    public c(int i, Map styles) {
        Intrinsics.checkNotNullParameter(styles, "styles");
        this.a = i;
        this.b = styles;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && this.b.equals(cVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "HeaderStyles(verticalPadding=" + this.a + ", styles=" + this.b + ')';
    }
}
