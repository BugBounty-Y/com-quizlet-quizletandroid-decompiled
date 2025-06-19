package androidx.compose.ui.text;

import java.util.ArrayList;
import java.util.List;

/* renamed from: androidx.compose.ui.text.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0996h {
    public static final C0995g a = new C0995g(6, "", null);

    public static final ArrayList a(int i, int i2, List list) {
        if (i > i2) {
            throw new IllegalArgumentException(("start (" + i + ") should be less than or equal to end (" + i2 + ')').toString());
        }
        if (list == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(list.size());
        int size = list.size();
        for (int i3 = 0; i3 < size; i3++) {
            Object obj = list.get(i3);
            C0985e c0985e = (C0985e) obj;
            if (c(i, i2, c0985e.b, c0985e.c)) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(arrayList.size());
        int size2 = arrayList.size();
        for (int i4 = 0; i4 < size2; i4++) {
            C0985e c0985e2 = (C0985e) arrayList.get(i4);
            arrayList2.add(new C0985e(Math.max(i, c0985e2.b) - i, Math.min(i2, c0985e2.c) - i, c0985e2.a, c0985e2.d));
        }
        if (arrayList2.isEmpty()) {
            return null;
        }
        return arrayList2;
    }

    public static final List b(C0995g c0995g, int i, int i2) {
        List list;
        if (i == i2 || (list = c0995g.b) == null) {
            return null;
        }
        if (i == 0 && i2 >= c0995g.a.length()) {
            return list;
        }
        ArrayList arrayList = new ArrayList(list.size());
        int size = list.size();
        for (int i3 = 0; i3 < size; i3++) {
            Object obj = list.get(i3);
            C0985e c0985e = (C0985e) obj;
            if (c(i, i2, c0985e.b, c0985e.c)) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(arrayList.size());
        int size2 = arrayList.size();
        for (int i4 = 0; i4 < size2; i4++) {
            C0985e c0985e2 = (C0985e) arrayList.get(i4);
            arrayList2.add(new C0985e(c0985e2.a, kotlin.ranges.l.c(c0985e2.b, i, i2) - i, kotlin.ranges.l.c(c0985e2.c, i, i2) - i));
        }
        return arrayList2;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x001f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean c(int r4, int r5, int r6, int r7) {
        /*
            int r0 = java.lang.Math.max(r4, r6)
            int r1 = java.lang.Math.min(r5, r7)
            r2 = 1
            if (r0 < r1) goto L33
            r0 = 0
            if (r4 > r6) goto L1f
            if (r7 > r5) goto L1f
            if (r5 != r7) goto L33
            if (r6 != r7) goto L16
            r1 = r2
            goto L17
        L16:
            r1 = r0
        L17:
            if (r4 != r5) goto L1b
            r3 = r2
            goto L1c
        L1b:
            r3 = r0
        L1c:
            if (r1 != r3) goto L1f
            goto L33
        L1f:
            if (r6 > r4) goto L32
            if (r5 > r7) goto L32
            if (r7 != r5) goto L33
            if (r4 != r5) goto L29
            r4 = r2
            goto L2a
        L29:
            r4 = r0
        L2a:
            if (r6 != r7) goto L2e
            r5 = r2
            goto L2f
        L2e:
            r5 = r0
        L2f:
            if (r4 != r5) goto L32
            goto L33
        L32:
            return r0
        L33:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.text.AbstractC0996h.c(int, int, int, int):boolean");
    }
}
