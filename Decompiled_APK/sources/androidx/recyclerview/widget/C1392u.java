package androidx.recyclerview.widget;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

/* renamed from: androidx.recyclerview.widget.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1392u {
    public final ArrayList a;
    public final int[] b;
    public final int[] c;
    public final AbstractC1389s d;
    public final int e;
    public final int f;
    public final boolean g;

    public C1392u(AbstractC1389s abstractC1389s, ArrayList arrayList, int[] iArr, int[] iArr2) {
        int[] iArr3;
        int[] iArr4;
        AbstractC1389s abstractC1389s2;
        int i;
        C1391t c1391t;
        int i2;
        this.a = arrayList;
        this.b = iArr;
        this.c = iArr2;
        Arrays.fill(iArr, 0);
        Arrays.fill(iArr2, 0);
        this.d = abstractC1389s;
        int oldListSize = abstractC1389s.getOldListSize();
        this.e = oldListSize;
        int newListSize = abstractC1389s.getNewListSize();
        this.f = newListSize;
        this.g = true;
        C1391t c1391t2 = arrayList.isEmpty() ? null : (C1391t) arrayList.get(0);
        if (c1391t2 == null || c1391t2.a != 0 || c1391t2.b != 0) {
            arrayList.add(0, new C1391t(0, 0, 0));
        }
        arrayList.add(new C1391t(oldListSize, newListSize, 0));
        Iterator it2 = arrayList.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            iArr3 = this.c;
            iArr4 = this.b;
            abstractC1389s2 = this.d;
            if (!zHasNext) {
                break;
            }
            C1391t c1391t3 = (C1391t) it2.next();
            for (int i3 = 0; i3 < c1391t3.c; i3++) {
                int i4 = c1391t3.a + i3;
                int i5 = c1391t3.b + i3;
                int i6 = abstractC1389s2.areContentsTheSame(i4, i5) ? 1 : 2;
                iArr4[i4] = (i5 << 4) | i6;
                iArr3[i5] = (i4 << 4) | i6;
            }
        }
        if (this.g) {
            Iterator it3 = arrayList.iterator();
            int i7 = 0;
            while (it3.hasNext()) {
                C1391t c1391t4 = (C1391t) it3.next();
                while (true) {
                    i = c1391t4.a;
                    if (i7 < i) {
                        if (iArr4[i7] == 0) {
                            int size = arrayList.size();
                            int i8 = 0;
                            int i9 = 0;
                            while (true) {
                                if (i8 < size) {
                                    c1391t = (C1391t) arrayList.get(i8);
                                    while (true) {
                                        i2 = c1391t.b;
                                        if (i9 < i2) {
                                            if (iArr3[i9] == 0 && abstractC1389s2.areItemsTheSame(i7, i9)) {
                                                int i10 = abstractC1389s2.areContentsTheSame(i7, i9) ? 8 : 4;
                                                iArr4[i7] = (i9 << 4) | i10;
                                                iArr3[i9] = i10 | (i7 << 4);
                                            } else {
                                                i9++;
                                            }
                                        }
                                    }
                                }
                                i9 = c1391t.c + i2;
                                i8++;
                            }
                        }
                        i7++;
                    }
                }
                i7 = c1391t4.c + i;
            }
        }
    }

    public static C1393v b(ArrayDeque arrayDeque, int i, boolean z) {
        C1393v c1393v;
        Iterator it2 = arrayDeque.iterator();
        while (true) {
            if (!it2.hasNext()) {
                c1393v = null;
                break;
            }
            c1393v = (C1393v) it2.next();
            if (c1393v.a == i && c1393v.c == z) {
                it2.remove();
                break;
            }
        }
        while (it2.hasNext()) {
            C1393v c1393v2 = (C1393v) it2.next();
            if (z) {
                c1393v2.b--;
            } else {
                c1393v2.b++;
            }
        }
        return c1393v;
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x00ef  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(androidx.recyclerview.widget.C1356b r19) {
        /*
            Method dump skipped, instructions count: 303
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.C1392u.a(androidx.recyclerview.widget.b):void");
    }
}
