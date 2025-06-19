package androidx.paging;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class M extends N {
    public final F a;
    public final F b;

    public M(F source, F f) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
        this.b = f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof M)) {
            return false;
        }
        M m = (M) obj;
        return Intrinsics.b(this.a, m.a) && Intrinsics.b(this.b, m.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        F f = this.b;
        return iHashCode + (f == null ? 0 : f.hashCode());
    }

    public final String toString() {
        String str = "PageEvent.LoadStateUpdate (\n                    |   sourceLoadStates: " + this.a + "\n                    ";
        F f = this.b;
        if (f != null) {
            str = str + "|   mediatorLoadStates: " + f + '\n';
        }
        return kotlin.text.x.d(str + "|)");
    }
}
