package androidx.paging;

/* loaded from: classes.dex */
public final class A0 extends AbstractC1348x {
    public final int b;
    public final int c;
    public final int d;
    public final int e;

    public A0(int i, int i2, int i3, int i4) {
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = i4;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof A0)) {
            return false;
        }
        A0 a0 = (A0) obj;
        return this.b == a0.b && this.c == a0.c && this.d == a0.d && this.e == a0.e;
    }

    public final int hashCode() {
        return Integer.hashCode(this.e) + Integer.hashCode(this.d) + Integer.hashCode(this.c) + Integer.hashCode(this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PagingDataEvent.DropAppend dropped ");
        int i = this.c;
        sb.append(i);
        sb.append(" items (\n                    |   startIndex: ");
        sb.append(this.b);
        sb.append("\n                    |   dropCount: ");
        sb.append(i);
        sb.append("\n                    |   newPlaceholdersBefore: ");
        sb.append(this.d);
        sb.append("\n                    |   oldPlaceholdersBefore: ");
        sb.append(this.e);
        sb.append("\n                    |)\n                    |");
        return kotlin.text.x.d(sb.toString());
    }
}
