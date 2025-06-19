package androidx.glance.semantics;

import androidx.glance.o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements o {
    public final a a;

    public b(a aVar) {
        this.a = aVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SemanticsModifier(configuration=" + this.a + ')';
    }
}
