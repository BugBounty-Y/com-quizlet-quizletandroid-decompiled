package androidx.paging;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class B extends E {
    public final Exception b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(Exception error) {
        super(false);
        Intrinsics.checkNotNullParameter(error, "error");
        this.b = error;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof B)) {
            return false;
        }
        B b = (B) obj;
        return this.a == b.a && this.b.equals(b.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + Boolean.hashCode(this.a);
    }

    public final String toString() {
        return "Error(endOfPaginationReached=" + this.a + ", error=" + this.b + ')';
    }
}
