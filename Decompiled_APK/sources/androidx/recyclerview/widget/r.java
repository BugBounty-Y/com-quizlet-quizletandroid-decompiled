package androidx.recyclerview.widget;

import java.util.Comparator;

/* loaded from: classes.dex */
public final class r implements Comparator {
    public final /* synthetic */ int a;

    public /* synthetic */ r(int i) {
        this.a = i;
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x001b, code lost:
    
        if (r0 == null) goto L19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0024, code lost:
    
        if (r0 != false) goto L18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0026, code lost:
    
        return -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:?, code lost:
    
        return 1;
     */
    @Override // java.util.Comparator
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int compare(java.lang.Object r6, java.lang.Object r7) {
        /*
            r5 = this;
            int r0 = r5.a
            switch(r0) {
                case 0: goto L3c;
                default: goto L5;
            }
        L5:
            androidx.recyclerview.widget.C r6 = (androidx.recyclerview.widget.C) r6
            androidx.recyclerview.widget.C r7 = (androidx.recyclerview.widget.C) r7
            androidx.recyclerview.widget.RecyclerView r0 = r6.d
            r1 = 0
            r2 = 1
            if (r0 != 0) goto L11
            r3 = r2
            goto L12
        L11:
            r3 = r1
        L12:
            androidx.recyclerview.widget.RecyclerView r4 = r7.d
            if (r4 != 0) goto L18
            r4 = r2
            goto L19
        L18:
            r4 = r1
        L19:
            if (r3 == r4) goto L1e
            if (r0 != 0) goto L26
            goto L28
        L1e:
            boolean r0 = r6.a
            boolean r3 = r7.a
            if (r0 == r3) goto L2a
            if (r0 == 0) goto L28
        L26:
            r1 = -1
            goto L3b
        L28:
            r1 = r2
            goto L3b
        L2a:
            int r0 = r7.b
            int r2 = r6.b
            int r0 = r0 - r2
            if (r0 == 0) goto L33
            r1 = r0
            goto L3b
        L33:
            int r6 = r6.c
            int r7 = r7.c
            int r6 = r6 - r7
            if (r6 == 0) goto L3b
            r1 = r6
        L3b:
            return r1
        L3c:
            androidx.recyclerview.widget.t r6 = (androidx.recyclerview.widget.C1391t) r6
            androidx.recyclerview.widget.t r7 = (androidx.recyclerview.widget.C1391t) r7
            int r6 = r6.a
            int r7 = r7.a
            int r6 = r6 - r7
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.r.compare(java.lang.Object, java.lang.Object):int");
    }
}
