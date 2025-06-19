package androidx.paging;

import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.paging.z0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1353z0 extends AbstractC1348x {
    public final int b;
    public final ArrayList c;
    public final int d;
    public final int e;

    public C1353z0(int i, ArrayList inserted, int i2, int i3) {
        Intrinsics.checkNotNullParameter(inserted, "inserted");
        this.b = i;
        this.c = inserted;
        this.d = i2;
        this.e = i3;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C1353z0)) {
            return false;
        }
        C1353z0 c1353z0 = (C1353z0) obj;
        return this.b == c1353z0.b && this.c.equals(c1353z0.c) && this.d == c1353z0.d && this.e == c1353z0.e;
    }

    public final int hashCode() {
        return Integer.hashCode(this.e) + Integer.hashCode(this.d) + this.c.hashCode() + Integer.hashCode(this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PagingDataEvent.Append loaded ");
        ArrayList arrayList = this.c;
        sb.append(arrayList.size());
        sb.append(" items (\n                    |   startIndex: ");
        sb.append(this.b);
        sb.append("\n                    |   first item: ");
        sb.append(CollectionsKt.firstOrNull(arrayList));
        sb.append("\n                    |   last item: ");
        sb.append(CollectionsKt.V(arrayList));
        sb.append("\n                    |   newPlaceholdersBefore: ");
        sb.append(this.d);
        sb.append("\n                    |   oldPlaceholdersBefore: ");
        sb.append(this.e);
        sb.append("\n                    |)\n                    |");
        return kotlin.text.x.d(sb.toString());
    }
}
