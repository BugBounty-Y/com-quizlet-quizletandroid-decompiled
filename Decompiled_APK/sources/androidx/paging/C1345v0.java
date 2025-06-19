package androidx.paging;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* renamed from: androidx.paging.v0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1345v0 {
    public static final C1345v0 e = new C1345v0(L.g);
    public final ArrayList a;
    public int b;
    public int c;
    public int d;

    public C1345v0(int i, int i2, List pages) {
        Intrinsics.checkNotNullParameter(pages, "pages");
        this.a = CollectionsKt.y0(pages);
        Iterator it2 = pages.iterator();
        int size = 0;
        while (it2.hasNext()) {
            size += ((g1) it2.next()).b.size();
        }
        this.b = size;
        this.c = i;
        this.d = i2;
    }

    public final i1 a(int i) {
        ArrayList arrayList;
        int i2 = 0;
        int size = i - this.c;
        while (true) {
            arrayList = this.a;
            if (size < ((g1) arrayList.get(i2)).b.size() || i2 >= kotlin.collections.B.i(arrayList)) {
                break;
            }
            size -= ((g1) arrayList.get(i2)).b.size();
            i2++;
        }
        g1 g1Var = (g1) arrayList.get(i2);
        int i3 = i - this.c;
        int iE = ((e() - i) - this.d) - 1;
        int iC = c();
        int iD = d();
        g1Var.getClass();
        return new i1(g1Var.c, size, i3, iE, iC, iD);
    }

    public final Object b(int i) {
        ArrayList arrayList = this.a;
        int size = arrayList.size();
        int i2 = 0;
        while (i2 < size) {
            int size2 = ((g1) arrayList.get(i2)).b.size();
            if (size2 > i) {
                break;
            }
            i -= size2;
            i2++;
        }
        return ((g1) arrayList.get(i2)).b.get(i);
    }

    public final int c() {
        Integer numValueOf;
        int[] iArr = ((g1) CollectionsKt.L(this.a)).a;
        Intrinsics.checkNotNullParameter(iArr, "<this>");
        if (iArr.length == 0) {
            numValueOf = null;
        } else {
            int i = iArr[0];
            Intrinsics.checkNotNullParameter(iArr, "<this>");
            int i2 = 1;
            int length = iArr.length - 1;
            if (1 <= length) {
                while (true) {
                    int i3 = iArr[i2];
                    if (i > i3) {
                        i = i3;
                    }
                    if (i2 == length) {
                        break;
                    }
                    i2++;
                }
            }
            numValueOf = Integer.valueOf(i);
        }
        Intrinsics.d(numValueOf);
        return numValueOf.intValue();
    }

    public final int d() {
        Integer numValueOf;
        int[] iArr = ((g1) CollectionsKt.U(this.a)).a;
        Intrinsics.checkNotNullParameter(iArr, "<this>");
        if (iArr.length == 0) {
            numValueOf = null;
        } else {
            int i = iArr[0];
            Intrinsics.checkNotNullParameter(iArr, "<this>");
            int i2 = 1;
            int length = iArr.length - 1;
            if (1 <= length) {
                while (true) {
                    int i3 = iArr[i2];
                    if (i < i3) {
                        i = i3;
                    }
                    if (i2 == length) {
                        break;
                    }
                    i2++;
                }
            }
            numValueOf = Integer.valueOf(i);
        }
        Intrinsics.d(numValueOf);
        return numValueOf.intValue();
    }

    public final int e() {
        return this.c + this.b + this.d;
    }

    public final AbstractC1348x f(N pageEvent) {
        Intrinsics.checkNotNullParameter(pageEvent, "pageEvent");
        boolean z = pageEvent instanceof L;
        ArrayList arrayList = this.a;
        if (!z) {
            if (!(pageEvent instanceof J)) {
                throw new IllegalStateException("Paging received an event to process StaticList or LoadStateUpdate while\nprocessing Inserts and Drops. If you see this exception, it is most\nlikely a bug in the library. Please file a bug so we can fix it at:\nhttps://issuetracker.google.com/issues/new?component=413106");
            }
            ((J) pageEvent).getClass();
            IntRange intRange = new IntRange(0, 0, 1);
            Iterator it2 = arrayList.iterator();
            int size = 0;
            while (it2.hasNext()) {
                g1 g1Var = (g1) it2.next();
                int[] iArr = g1Var.a;
                int length = iArr.length;
                int i = 0;
                while (true) {
                    if (i >= length) {
                        break;
                    }
                    if (intRange.b(iArr[i])) {
                        size += g1Var.b.size();
                        it2.remove();
                        break;
                    }
                    i++;
                }
            }
            int i2 = this.b - size;
            this.b = i2;
            int i3 = this.d;
            this.d = 0;
            return new A0(this.c + i2, size, 0, i3);
        }
        L l = (L) pageEvent;
        Iterator it3 = l.b.iterator();
        int size2 = 0;
        while (it3.hasNext()) {
            size2 += ((g1) it3.next()).b.size();
        }
        int iOrdinal = l.a.ordinal();
        if (iOrdinal == 0) {
            throw new IllegalStateException("Paging received a refresh event in the middle of an actively loading generation\nof PagingData. If you see this exception, it is most likely a bug in the library.\nPlease file a bug so we can fix it at:\nhttps://issuetracker.google.com/issues/new?component=413106");
        }
        List list = l.b;
        if (iOrdinal == 1) {
            int i4 = this.c;
            arrayList.addAll(0, list);
            this.b += size2;
            this.c = l.c;
            ArrayList arrayList2 = new ArrayList();
            Iterator it4 = list.iterator();
            while (it4.hasNext()) {
                kotlin.collections.G.u(arrayList2, ((g1) it4.next()).b);
            }
            return new C0(arrayList2, this.c, i4);
        }
        if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        int i5 = this.d;
        int i6 = this.b;
        arrayList.addAll(arrayList.size(), list);
        this.b += size2;
        this.d = l.d;
        int i7 = this.c + i6;
        ArrayList arrayList3 = new ArrayList();
        Iterator it5 = list.iterator();
        while (it5.hasNext()) {
            kotlin.collections.G.u(arrayList3, ((g1) it5.next()).b);
        }
        return new C1353z0(i7, arrayList3, this.d, i5);
    }

    public final String toString() {
        int i = this.b;
        ArrayList arrayList = new ArrayList(i);
        for (int i2 = 0; i2 < i; i2++) {
            arrayList.add(b(i2));
        }
        String strS = CollectionsKt.S(arrayList, null, null, null, null, 63);
        StringBuilder sb = new StringBuilder("[(");
        sb.append(this.c);
        sb.append(" placeholders), ");
        sb.append(strS);
        sb.append(", (");
        return android.support.v4.media.session.a.r(sb, this.d, " placeholders)]");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C1345v0(L insertEvent) {
        this(insertEvent.c, insertEvent.d, insertEvent.b);
        Intrinsics.checkNotNullParameter(insertEvent, "insertEvent");
    }
}
