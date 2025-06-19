package androidx.compose.runtime.collection;

import kotlin.Unit;
import kotlin.coroutines.jvm.internal.h;
import kotlin.jvm.functions.Function2;
import kotlin.sequences.i;

/* loaded from: classes.dex */
public final class d extends h implements Function2 {
    public Object[] k;
    public long[] l;
    public int m;
    public int n;
    public int o;
    public int p;
    public long q;
    public int r;
    public /* synthetic */ Object s;
    public final /* synthetic */ e t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e eVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.t = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.t, hVar);
        dVar.s = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((i) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0095  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:12:0x004f -> B:22:0x0093). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:13:0x0051 -> B:14:0x0062). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:16:0x006b -> B:19:0x008a). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r21) {
        /*
            r20 = this;
            r0 = r20
            r1 = 1
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r0.r
            r4 = 0
            r5 = 8
            if (r3 == 0) goto L2c
            if (r3 != r1) goto L24
            int r3 = r0.p
            int r6 = r0.o
            long r7 = r0.q
            int r9 = r0.n
            int r10 = r0.m
            long[] r11 = r0.l
            java.lang.Object[] r12 = r0.k
            java.lang.Object r13 = r0.s
            kotlin.sequences.i r13 = (kotlin.sequences.i) r13
            androidx.glance.appwidget.protobuf.Z.e(r21)
            goto L8a
        L24:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L2c:
            androidx.glance.appwidget.protobuf.Z.e(r21)
            java.lang.Object r3 = r0.s
            kotlin.sequences.i r3 = (kotlin.sequences.i) r3
            androidx.compose.runtime.collection.e r6 = r0.t
            androidx.collection.J r6 = r6.a
            java.lang.Object[] r7 = r6.b
            long[] r6 = r6.a
            int r8 = r6.length
            int r8 = r8 + (-2)
            if (r8 < 0) goto L97
            r9 = r4
        L41:
            r10 = r6[r9]
            long r12 = ~r10
            r14 = 7
            long r12 = r12 << r14
            long r12 = r12 & r10
            r14 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r12 = r12 & r14
            int r12 = (r12 > r14 ? 1 : (r12 == r14 ? 0 : -1))
            if (r12 == 0) goto L93
            int r12 = r9 - r8
            int r12 = ~r12
            int r12 = r12 >>> 31
            int r12 = 8 - r12
            r13 = r3
            r3 = r4
            r18 = r10
            r11 = r6
            r10 = r8
            r6 = r12
            r12 = r7
            r7 = r18
        L62:
            if (r3 >= r6) goto L8d
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r7
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L8a
            int r4 = r9 << 3
            int r4 = r4 + r3
            r4 = r12[r4]
            r0.s = r13
            r0.k = r12
            r0.l = r11
            r0.m = r10
            r0.n = r9
            r0.q = r7
            r0.o = r6
            r0.p = r3
            r0.r = r1
            r13.a(r4, r0)
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            return r2
        L8a:
            long r7 = r7 >> r5
            int r3 = r3 + r1
            goto L62
        L8d:
            if (r6 != r5) goto L97
            r8 = r10
            r6 = r11
            r7 = r12
            r3 = r13
        L93:
            if (r9 == r8) goto L97
            int r9 = r9 + r1
            goto L41
        L97:
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.collection.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
