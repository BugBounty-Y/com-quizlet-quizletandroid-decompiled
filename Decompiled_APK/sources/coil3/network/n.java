package coil3.network;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;

/* loaded from: classes.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public J j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ J m;
    public final /* synthetic */ q n;
    public final /* synthetic */ J o;
    public final /* synthetic */ s p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(J j, q qVar, J j2, s sVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = j;
        this.n = qVar;
        this.o = j2;
        this.p = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        n nVar = new n(this.m, this.n, this.o, this.p, hVar);
        nVar.l = obj;
        return nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((t) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x009e  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00bb A[RETURN] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) throws java.lang.Exception {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.k
            coil3.network.q r2 = r9.n
            r3 = 0
            r4 = 2
            r5 = 1
            kotlin.jvm.internal.J r6 = r9.o
            kotlin.jvm.internal.J r7 = r9.m
            if (r1 == 0) goto L2e
            if (r1 == r5) goto L24
            if (r1 != r4) goto L1c
            java.lang.Object r0 = r9.l
            coil3.network.t r0 = (coil3.network.t) r0
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L94
        L1c:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L24:
            kotlin.jvm.internal.J r1 = r9.j
            java.lang.Object r5 = r9.l
            coil3.network.t r5 = (coil3.network.t) r5
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L4d
        L2e:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.lang.Object r10 = r9.l
            coil3.network.t r10 = (coil3.network.t) r10
            java.lang.Object r1 = r7.a
            coil3.disk.h r1 = (coil3.disk.h) r1
            java.lang.Object r8 = r6.a
            coil3.network.t r8 = (coil3.network.t) r8
            r9.l = r10
            r9.j = r7
            r9.k = r5
            java.lang.Object r1 = coil3.network.q.c(r2, r1, r8, r10, r9)
            if (r1 != r0) goto L4a
            goto L92
        L4a:
            r5 = r10
            r10 = r1
            r1 = r7
        L4d:
            r1.a = r10
            java.lang.Object r10 = r7.a
            if (r10 == 0) goto L82
            coil3.disk.h r10 = (coil3.disk.h) r10
            coil3.network.t r10 = r2.i(r10)
            r6.a = r10
            coil3.fetch.i r10 = new coil3.fetch.i
            java.lang.Object r0 = r7.a
            kotlin.jvm.internal.Intrinsics.d(r0)
            coil3.disk.h r0 = (coil3.disk.h) r0
            coil3.decode.p r0 = r2.h(r0)
            java.lang.Object r1 = r6.a
            coil3.network.t r1 = (coil3.network.t) r1
            if (r1 == 0) goto L76
            coil3.network.r r1 = r1.d
            if (r1 == 0) goto L76
            java.lang.String r3 = r1.a()
        L76:
            java.lang.String r1 = r2.a
            java.lang.String r1 = coil3.network.q.f(r1, r3)
            coil3.decode.h r2 = coil3.decode.h.d
            r10.<init>(r0, r1, r2)
            return r10
        L82:
            coil3.network.u r10 = r5.e
            if (r10 == 0) goto Lbc
            r9.l = r5
            r9.j = r3
            r9.k = r4
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_common.AbstractC3455g.a(r10, r9)
            if (r10 != r0) goto L93
        L92:
            return r0
        L93:
            r0 = r5
        L94:
            okio.h r10 = (okio.C5091h) r10
            long r4 = r10.b
            r6 = 0
            int r1 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r1 <= 0) goto Lbb
            coil3.fetch.i r1 = new coil3.fetch.i
            okio.n r4 = r2.e()
            coil3.decode.s r5 = new coil3.decode.s
            r5.<init>(r10, r4, r3)
            coil3.network.r r10 = r0.d
            java.lang.String r10 = r10.a()
            java.lang.String r0 = r2.a
            java.lang.String r10 = coil3.network.q.f(r0, r10)
            coil3.decode.h r0 = coil3.decode.h.d
            r1.<init>(r5, r10, r0)
            return r1
        Lbb:
            return r3
        Lbc:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "body == null"
            r10.<init>(r0)
            throw r10
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.network.n.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
