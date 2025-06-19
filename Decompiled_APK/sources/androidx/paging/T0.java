package androidx.paging;

import androidx.compose.material3.C0676l1;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class T0 {
    public final List a;
    public final Integer b;
    public final C0676l1 c;
    public final int d;

    public T0(List pages, Integer num, C0676l1 config, int i) {
        Intrinsics.checkNotNullParameter(pages, "pages");
        Intrinsics.checkNotNullParameter(config, "config");
        this.a = pages;
        this.b = num;
        this.c = config;
        this.d = i;
    }

    public final P0 a(int i) {
        List list = this.a;
        if (list != null && list.isEmpty()) {
            return null;
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            if (!((P0) it2.next()).a.isEmpty()) {
                int size = i - this.d;
                int i2 = 0;
                while (i2 < kotlin.collections.B.i(list) && size > kotlin.collections.B.i(((P0) list.get(i2)).a)) {
                    size -= ((P0) list.get(i2)).a.size();
                    i2++;
                }
                return size < 0 ? (P0) CollectionsKt.L(list) : (P0) list.get(i2);
            }
        }
        return null;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof T0)) {
            return false;
        }
        T0 t0 = (T0) obj;
        return Intrinsics.b(this.a, t0.a) && Intrinsics.b(this.b, t0.b) && Intrinsics.b(this.c, t0.c) && this.d == t0.d;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode();
        Integer num = this.b;
        return Integer.hashCode(this.d) + this.c.hashCode() + iHashCode + (num != null ? num.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PagingState(pages=");
        sb.append(this.a);
        sb.append(", anchorPosition=");
        sb.append(this.b);
        sb.append(", config=");
        sb.append(this.c);
        sb.append(", leadingPlaceholderCount=");
        return android.support.v4.media.session.a.q(sb, this.d, ')');
    }
}
