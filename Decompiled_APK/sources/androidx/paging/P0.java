package androidx.paging;

import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class P0 extends Q0 implements Iterable, kotlin.jvm.internal.markers.a {
    public final List a;
    public final Integer b;
    public final Integer c;
    public final int d;
    public final int e;

    static {
        new P0(kotlin.collections.K.a, null, null, 0, 0);
    }

    public P0(List data, Integer num, Integer num2, int i, int i2) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
        this.b = num;
        this.c = num2;
        this.d = i;
        this.e = i2;
        if (i != Integer.MIN_VALUE && i < 0) {
            throw new IllegalArgumentException("itemsBefore cannot be negative");
        }
        if (i2 != Integer.MIN_VALUE && i2 < 0) {
            throw new IllegalArgumentException("itemsAfter cannot be negative");
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof P0)) {
            return false;
        }
        P0 p0 = (P0) obj;
        return Intrinsics.b(this.a, p0.a) && Intrinsics.b(this.b, p0.b) && Intrinsics.b(this.c, p0.c) && this.d == p0.d && this.e == p0.e;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Integer num = this.b;
        int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.c;
        return Integer.hashCode(this.e) + androidx.compose.animation.d0.b(this.d, (iHashCode2 + (num2 != null ? num2.hashCode() : 0)) * 31, 31);
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return this.a.listIterator();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LoadResult.Page(\n                    |   data size: ");
        List list = this.a;
        sb.append(list.size());
        sb.append("\n                    |   first Item: ");
        sb.append(CollectionsKt.firstOrNull(list));
        sb.append("\n                    |   last Item: ");
        sb.append(CollectionsKt.V(list));
        sb.append("\n                    |   nextKey: ");
        sb.append(this.c);
        sb.append("\n                    |   prevKey: ");
        sb.append(this.b);
        sb.append("\n                    |   itemsBefore: ");
        sb.append(this.d);
        sb.append("\n                    |   itemsAfter: ");
        sb.append(this.e);
        sb.append("\n                    |) ");
        return kotlin.text.x.d(sb.toString());
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public P0(List data, Integer num, Integer num2) {
        this(data, num, num2, Integer.MIN_VALUE, Integer.MIN_VALUE);
        Intrinsics.checkNotNullParameter(data, "data");
    }
}
