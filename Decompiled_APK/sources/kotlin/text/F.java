package kotlin.text;

import java.util.List;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class F extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ List a;
    public final /* synthetic */ boolean b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(List list, boolean z) {
        super(2);
        this.a = list;
        this.b = z;
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x00bc A[EDGE_INSN: B:56:0x00bc->B:50:0x00bc BREAK  A[LOOP:0: B:20:0x004b->B:31:0x007c], EDGE_INSN: B:60:0x00bc->B:50:0x00bc BREAK  A[LOOP:2: B:37:0x0087->B:49:0x00b9]] */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00bc A[EDGE_INSN: B:56:0x00bc->B:50:0x00bc BREAK  A[LOOP:0: B:20:0x004b->B:31:0x007c]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final kotlin.Pair<java.lang.Integer, java.lang.Integer> a(java.lang.CharSequence r12, int r13) {
        /*
            r11 = this;
            java.lang.String r0 = "$this$$receiver"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r0)
            r0 = 0
            r1 = 0
            java.util.List r2 = r11.a
            boolean r8 = r11.b
            r3 = 1
            if (r8 != 0) goto L2e
            int r4 = r2.size()
            if (r4 != r3) goto L2e
            java.lang.Object r2 = kotlin.collections.CollectionsKt.i0(r2)
            java.lang.String r2 = (java.lang.String) r2
            r3 = 4
            int r12 = kotlin.text.StringsKt.M(r12, r2, r13, r0, r3)
            if (r12 >= 0) goto L23
            goto Lbc
        L23:
            java.lang.Integer r12 = java.lang.Integer.valueOf(r12)
            kotlin.Pair r13 = new kotlin.Pair
            r13.<init>(r12, r2)
            goto Lbd
        L2e:
            kotlin.ranges.IntRange r4 = new kotlin.ranges.IntRange
            if (r13 >= 0) goto L33
            r13 = r0
        L33:
            int r0 = r12.length()
            r4.<init>(r13, r0, r3)
            boolean r0 = r12 instanceof java.lang.String
            int r9 = r4.c
            int r10 = r4.b
            if (r0 == 0) goto L7e
            if (r9 <= 0) goto L46
            if (r13 <= r10) goto L4a
        L46:
            if (r9 >= 0) goto Lbc
            if (r10 > r13) goto Lbc
        L4a:
            r4 = r13
        L4b:
            java.util.Iterator r13 = r2.iterator()
        L4f:
            boolean r0 = r13.hasNext()
            if (r0 == 0) goto L6b
            java.lang.Object r0 = r13.next()
            r6 = r0
            java.lang.String r6 = (java.lang.String) r6
            r7 = r12
            java.lang.String r7 = (java.lang.String) r7
            int r5 = r6.length()
            r3 = 0
            boolean r3 = kotlin.text.D.m(r3, r4, r5, r6, r7, r8)
            if (r3 == 0) goto L4f
            goto L6c
        L6b:
            r0 = r1
        L6c:
            java.lang.String r0 = (java.lang.String) r0
            if (r0 == 0) goto L7a
            java.lang.Integer r12 = java.lang.Integer.valueOf(r4)
            kotlin.Pair r13 = new kotlin.Pair
            r13.<init>(r12, r0)
            goto Lbd
        L7a:
            if (r4 == r10) goto Lbc
            int r4 = r4 + r9
            goto L4b
        L7e:
            if (r9 <= 0) goto L82
            if (r13 <= r10) goto L86
        L82:
            if (r9 >= 0) goto Lbc
            if (r10 > r13) goto Lbc
        L86:
            r6 = r13
        L87:
            java.util.Iterator r13 = r2.iterator()
        L8b:
            boolean r0 = r13.hasNext()
            if (r0 == 0) goto La7
            java.lang.Object r0 = r13.next()
            r3 = r0
            java.lang.String r3 = (java.lang.String) r3
            int r7 = r3.length()
            r4 = 0
            r5 = r12
            boolean r12 = kotlin.text.StringsKt__StringsKt.x(r3, r4, r5, r6, r7, r8)
            if (r12 == 0) goto La5
            goto La9
        La5:
            r12 = r5
            goto L8b
        La7:
            r5 = r12
            r0 = r1
        La9:
            java.lang.String r0 = (java.lang.String) r0
            if (r0 == 0) goto Lb7
            java.lang.Integer r12 = java.lang.Integer.valueOf(r6)
            kotlin.Pair r13 = new kotlin.Pair
            r13.<init>(r12, r0)
            goto Lbd
        Lb7:
            if (r6 == r10) goto Lbc
            int r6 = r6 + r9
            r12 = r5
            goto L87
        Lbc:
            r13 = r1
        Lbd:
            if (r13 == 0) goto Ld3
            java.lang.Object r12 = r13.b
            java.lang.String r12 = (java.lang.String) r12
            int r12 = r12.length()
            java.lang.Integer r12 = java.lang.Integer.valueOf(r12)
            kotlin.Pair r0 = new kotlin.Pair
            java.lang.Object r13 = r13.a
            r0.<init>(r13, r12)
            return r0
        Ld3:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.text.F.a(java.lang.CharSequence, int):kotlin.Pair");
    }

    @Override // kotlin.jvm.functions.Function2
    public final /* bridge */ /* synthetic */ Object invoke(Object obj, Object obj2) {
        return a((CharSequence) obj, ((Number) obj2).intValue());
    }
}
