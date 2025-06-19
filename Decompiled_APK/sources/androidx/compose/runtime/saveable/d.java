package androidx.compose.runtime.saveable;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d extends r implements Function2 {
    public static final d b = new d(2, 0);
    public static final d c = new d(2, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(int i, int i2) {
        super(i);
        this.a = i2;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x006a  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r18, java.lang.Object r19) {
        /*
            r17 = this;
            r0 = r17
            int r1 = r0.a
            switch(r1) {
                case 0: goto Lc;
                default: goto L7;
            }
        L7:
            r1 = r18
            androidx.compose.runtime.saveable.b r1 = (androidx.compose.runtime.saveable.b) r1
            return r19
        Lc:
            r1 = r18
            androidx.compose.runtime.saveable.b r1 = (androidx.compose.runtime.saveable.b) r1
            r1 = r19
            androidx.compose.runtime.saveable.f r1 = (androidx.compose.runtime.saveable.f) r1
            androidx.collection.I r2 = r1.b
            java.lang.Object[] r3 = r2.b
            java.lang.Object[] r4 = r2.c
            long[] r2 = r2.a
            int r5 = r2.length
            int r5 = r5 + (-2)
            java.util.Map r1 = r1.a
            if (r5 < 0) goto L6f
            r6 = 0
            r7 = r6
        L25:
            r8 = r2[r7]
            long r10 = ~r8
            r12 = 7
            long r10 = r10 << r12
            long r10 = r10 & r8
            r12 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r10 = r10 & r12
            int r10 = (r10 > r12 ? 1 : (r10 == r12 ? 0 : -1))
            if (r10 == 0) goto L6a
            int r10 = r7 - r5
            int r10 = ~r10
            int r10 = r10 >>> 31
            r11 = 8
            int r10 = 8 - r10
            r12 = r6
        L3f:
            if (r12 >= r10) goto L68
            r13 = 255(0xff, double:1.26E-321)
            long r13 = r13 & r8
            r15 = 128(0x80, double:6.3E-322)
            int r13 = (r13 > r15 ? 1 : (r13 == r15 ? 0 : -1))
            if (r13 >= 0) goto L64
            int r13 = r7 << 3
            int r13 = r13 + r12
            r14 = r3[r13]
            r13 = r4[r13]
            androidx.compose.runtime.saveable.i r13 = (androidx.compose.runtime.saveable.i) r13
            java.util.Map r13 = r13.b()
            boolean r15 = r13.isEmpty()
            if (r15 == 0) goto L61
            r1.remove(r14)
            goto L64
        L61:
            r1.put(r14, r13)
        L64:
            long r8 = r8 >> r11
            int r12 = r12 + 1
            goto L3f
        L68:
            if (r10 != r11) goto L6f
        L6a:
            if (r7 == r5) goto L6f
            int r7 = r7 + 1
            goto L25
        L6f:
            boolean r2 = r1.isEmpty()
            if (r2 == 0) goto L76
            r1 = 0
        L76:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.saveable.d.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
