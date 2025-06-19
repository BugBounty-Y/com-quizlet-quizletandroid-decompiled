package androidx.paging;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class O0 extends Q0 {
    public final Exception a;

    public O0(Exception throwable) {
        Intrinsics.checkNotNullParameter(throwable, "throwable");
        this.a = throwable;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof O0) && this.a.equals(((O0) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return kotlin.text.x.d("LoadResult.Error(\n                    |   throwable: " + this.a + "\n                    |) ");
    }
}
