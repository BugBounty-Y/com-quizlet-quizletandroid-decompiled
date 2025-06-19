package androidx.collection;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class K extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public L k;
    public M l;
    public long[] m;
    public int n;
    public int o;
    public int p;
    public int q;
    public long r;
    public int s;
    public /* synthetic */ Object t;
    public final /* synthetic */ M u;
    public final /* synthetic */ L v;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(M m, L l, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.u = m;
        this.v = l;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        K k = new K(this.u, this.v, hVar);
        k.t = obj;
        return k;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlin.sequences.i) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0054  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0069  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x00a4  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:12:0x0052 -> B:22:0x00a2). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:13:0x0054 -> B:14:0x0067). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:16:0x0070 -> B:19:0x0097). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r22) {
        /*
            r21 = this;
            r0 = r21
            r1 = 1
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r0.s
            r4 = 0
            r5 = 8
            if (r3 == 0) goto L2f
            if (r3 != r1) goto L27
            int r3 = r0.q
            int r6 = r0.p
            long r7 = r0.r
            int r9 = r0.o
            int r10 = r0.n
            long[] r11 = r0.m
            androidx.collection.M r12 = r0.l
            androidx.collection.L r13 = r0.k
            java.lang.Object r14 = r0.t
            kotlin.sequences.i r14 = (kotlin.sequences.i) r14
            androidx.glance.appwidget.protobuf.Z.e(r22)
            goto L97
        L27:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r22)
            java.lang.Object r3 = r0.t
            kotlin.sequences.i r3 = (kotlin.sequences.i) r3
            androidx.collection.M r6 = r0.u
            androidx.collection.J r7 = r6.b
            long[] r7 = r7.a
            int r8 = r7.length
            int r8 = r8 + (-2)
            if (r8 < 0) goto La6
            androidx.collection.L r9 = r0.v
            r10 = r4
        L44:
            r11 = r7[r10]
            long r13 = ~r11
            r15 = 7
            long r13 = r13 << r15
            long r13 = r13 & r11
            r15 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r13 = r13 & r15
            int r13 = (r13 > r15 ? 1 : (r13 == r15 ? 0 : -1))
            if (r13 == 0) goto La2
            int r13 = r10 - r8
            int r13 = ~r13
            int r13 = r13 >>> 31
            int r13 = 8 - r13
            r14 = r3
            r3 = r4
            r19 = r11
            r12 = r6
            r11 = r7
            r6 = r13
            r13 = r9
            r9 = r10
            r10 = r8
            r7 = r19
        L67:
            if (r3 >= r6) goto L9a
            r15 = 255(0xff, double:1.26E-321)
            long r15 = r15 & r7
            r17 = 128(0x80, double:6.3E-322)
            int r15 = (r15 > r17 ? 1 : (r15 == r17 ? 0 : -1))
            if (r15 >= 0) goto L97
            int r4 = r9 << 3
            int r4 = r4 + r3
            r13.b = r4
            androidx.collection.J r5 = r12.b
            java.lang.Object[] r5 = r5.b
            r4 = r5[r4]
            r0.t = r14
            r0.k = r13
            r0.l = r12
            r0.m = r11
            r0.n = r10
            r0.o = r9
            r0.r = r7
            r0.p = r6
            r0.q = r3
            r0.s = r1
            r14.a(r4, r0)
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            return r2
        L97:
            long r7 = r7 >> r5
            int r3 = r3 + r1
            goto L67
        L9a:
            if (r6 != r5) goto La6
            r8 = r10
            r7 = r11
            r6 = r12
            r3 = r14
            r10 = r9
            r9 = r13
        La2:
            if (r10 == r8) goto La6
            int r10 = r10 + r1
            goto L44
        La6:
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.collection.K.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
