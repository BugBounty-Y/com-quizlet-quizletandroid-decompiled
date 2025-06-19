package androidx.paging;

/* loaded from: classes.dex */
public final class B0 extends AbstractC1348x {
    public final int b;
    public final int c;
    public final int d;

    public B0(int i, int i2, int i3) {
        this.b = i;
        this.c = i2;
        this.d = i3;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof B0)) {
            return false;
        }
        B0 b0 = (B0) obj;
        return this.b == b0.b && this.c == b0.c && this.d == b0.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + Integer.hashCode(this.c) + Integer.hashCode(this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PagingDataEvent.DropPrepend dropped ");
        int i = this.b;
        sb.append(i);
        sb.append(" items (\n                    |   dropCount: ");
        sb.append(i);
        sb.append("\n                    |   newPlaceholdersBefore: ");
        sb.append(this.c);
        sb.append("\n                    |   oldPlaceholdersBefore: ");
        sb.append(this.d);
        sb.append("\n                    |)\n                    |");
        return kotlin.text.x.d(sb.toString());
    }
}
