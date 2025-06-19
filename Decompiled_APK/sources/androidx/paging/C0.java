package androidx.paging;

import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class C0 extends AbstractC1348x {
    public final ArrayList b;
    public final int c;
    public final int d;

    public C0(ArrayList inserted, int i, int i2) {
        Intrinsics.checkNotNullParameter(inserted, "inserted");
        this.b = inserted;
        this.c = i;
        this.d = i2;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C0)) {
            return false;
        }
        C0 c0 = (C0) obj;
        return this.b.equals(c0.b) && this.c == c0.c && this.d == c0.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + Integer.hashCode(this.c) + this.b.hashCode();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PagingDataEvent.Prepend loaded ");
        ArrayList arrayList = this.b;
        sb.append(arrayList.size());
        sb.append(" items (\n                    |   first item: ");
        sb.append(CollectionsKt.firstOrNull(arrayList));
        sb.append("\n                    |   last item: ");
        sb.append(CollectionsKt.V(arrayList));
        sb.append("\n                    |   newPlaceholdersBefore: ");
        sb.append(this.c);
        sb.append("\n                    |   oldPlaceholdersBefore: ");
        sb.append(this.d);
        sb.append("\n                    |)\n                    |");
        return kotlin.text.x.d(sb.toString());
    }
}
