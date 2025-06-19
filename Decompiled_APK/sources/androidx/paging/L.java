package androidx.paging;

import com.comscore.android.id.IdHelperAndroid;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L extends N {
    public static final L g;
    public final G a;
    public final List b;
    public final int c;
    public final int d;
    public final F e;
    public final F f;

    static {
        List listB = kotlin.collections.A.b(g1.d);
        D d = D.c;
        D d2 = D.b;
        g = AbstractC1348x.a(listB, 0, 0, new F(d, d2, d2), null);
    }

    public L(G g2, List list, int i, int i2, F f, F f2) {
        this.a = g2;
        this.b = list;
        this.c = i;
        this.d = i2;
        this.e = f;
        this.f = f2;
        if (g2 != G.c && i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Prepend insert defining placeholdersBefore must be > 0, but was ").toString());
        }
        if (g2 != G.b && i2 < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "Append insert defining placeholdersAfter must be > 0, but was ").toString());
        }
        if (g2 == G.a && list.isEmpty()) {
            throw new IllegalArgumentException("Cannot create a REFRESH Insert event with no TransformablePages as this could permanently stall pagination. Note that this check does not prevent empty LoadResults and is instead usually an indication of an internal error in Paging itself.");
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x00a4  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /* JADX WARN: Type inference failed for: r13v9, types: [java.util.Collection] */
    /* JADX WARN: Type inference failed for: r7v10, types: [java.util.Collection] */
    /* JADX WARN: Type inference failed for: r9v9, types: [java.util.Collection] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:17:0x0081 -> B:18:0x009e). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:23:0x00d1 -> B:24:0x00dc). Please report as a decompilation issue!!! */
    @Override // androidx.paging.N
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.jvm.functions.Function2 r18, kotlin.coroutines.h r19) {
        /*
            Method dump skipped, instructions count: 267
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.L.a(kotlin.jvm.functions.Function2, kotlin.coroutines.h):java.lang.Object");
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L)) {
            return false;
        }
        L l = (L) obj;
        return this.a == l.a && Intrinsics.b(this.b, l.b) && this.c == l.c && this.d == l.d && Intrinsics.b(this.e, l.e) && Intrinsics.b(this.f, l.f);
    }

    public final int hashCode() {
        int iHashCode = (this.e.hashCode() + androidx.compose.animation.d0.b(this.d, androidx.compose.animation.d0.b(this.c, androidx.compose.animation.d0.f(this.a.hashCode() * 31, 31, this.b), 31), 31)) * 31;
        F f = this.f;
        return iHashCode + (f == null ? 0 : f.hashCode());
    }

    public final String toString() {
        List list;
        List list2;
        List list3 = this.b;
        Iterator it2 = list3.iterator();
        int size = 0;
        while (it2.hasNext()) {
            size += ((g1) it2.next()).b.size();
        }
        String strValueOf = IdHelperAndroid.NO_ID_AVAILABLE;
        int i = this.c;
        String strValueOf2 = i != -1 ? String.valueOf(i) : IdHelperAndroid.NO_ID_AVAILABLE;
        int i2 = this.d;
        if (i2 != -1) {
            strValueOf = String.valueOf(i2);
        }
        StringBuilder sb = new StringBuilder("PageEvent.Insert for ");
        sb.append(this.a);
        sb.append(", with ");
        sb.append(size);
        sb.append(" items (\n                    |   first item: ");
        g1 g1Var = (g1) CollectionsKt.firstOrNull(list3);
        Object objV = null;
        sb.append((g1Var == null || (list2 = g1Var.b) == null) ? null : CollectionsKt.firstOrNull(list2));
        sb.append("\n                    |   last item: ");
        g1 g1Var2 = (g1) CollectionsKt.V(list3);
        if (g1Var2 != null && (list = g1Var2.b) != null) {
            objV = CollectionsKt.V(list);
        }
        sb.append(objV);
        sb.append("\n                    |   placeholdersBefore: ");
        sb.append(strValueOf2);
        sb.append("\n                    |   placeholdersAfter: ");
        sb.append(strValueOf);
        sb.append("\n                    |   sourceLoadStates: ");
        sb.append(this.e);
        sb.append("\n                    ");
        String string = sb.toString();
        F f = this.f;
        if (f != null) {
            string = string + "|   mediatorLoadStates: " + f + '\n';
        }
        return kotlin.text.x.d(string + "|)");
    }
}
