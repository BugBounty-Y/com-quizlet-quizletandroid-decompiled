package androidx.compose.animation.core;

import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class M extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlin.jvm.internal.G j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ InterfaceC0773a0 m;
    public final /* synthetic */ N n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(InterfaceC0773a0 interfaceC0773a0, N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = interfaceC0773a0;
        this.n = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        M m = new M(this.m, this.n, hVar);
        m.l = obj;
        return m;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((M) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    /* JADX WARN: Path cross not found for [B:11:0x003e, B:16:0x005c], limit reached: 18 */
    /* JADX WARN: Path cross not found for [B:16:0x005c, B:11:0x003e], limit reached: 18 */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0055 A[PHI: r8 r9
  0x0055: PHI (r8v1 kotlin.jvm.internal.G) = (r8v2 kotlin.jvm.internal.G), (r8v3 kotlin.jvm.internal.G) binds: [B:12:0x0052, B:9:0x0020] A[DONT_GENERATE, DONT_INLINE]
  0x0055: PHI (r9v1 kotlinx.coroutines.C) = (r9v2 kotlinx.coroutines.C), (r9v3 kotlinx.coroutines.C) binds: [B:12:0x0052, B:9:0x0020] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:16:0x005c  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:15:0x005a -> B:11:0x003e). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:17:0x0076 -> B:11:0x003e). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) {
        /*
            r11 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r11.k
            r2 = 1
            r3 = 2
            if (r1 == 0) goto L2c
            if (r1 == r2) goto L20
            if (r1 != r3) goto L18
            kotlin.jvm.internal.G r1 = r11.j
            java.lang.Object r4 = r11.l
            kotlinx.coroutines.C r4 = (kotlinx.coroutines.C) r4
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r8 = r1
            r9 = r4
            goto L3e
        L18:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L20:
            kotlin.jvm.internal.G r1 = r11.j
            java.lang.Object r4 = r11.l
            kotlinx.coroutines.C r4 = (kotlinx.coroutines.C) r4
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r8 = r1
            r9 = r4
            goto L55
        L2c:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.lang.Object r12 = r11.l
            kotlinx.coroutines.C r12 = (kotlinx.coroutines.C) r12
            kotlin.jvm.internal.G r1 = new kotlin.jvm.internal.G
            r1.<init>()
            r4 = 1065353216(0x3f800000, float:1.0)
            r1.a = r4
            r9 = r12
            r8 = r1
        L3e:
            androidx.compose.animation.core.a r5 = new androidx.compose.animation.core.a
            androidx.compose.runtime.a0 r6 = r11.m
            androidx.compose.animation.core.N r7 = r11.n
            r10 = 1
            r5.<init>(r6, r7, r8, r9, r10)
            r11.l = r9
            r11.j = r8
            r11.k = r2
            java.lang.Object r12 = androidx.compose.animation.core.AbstractC0240f.t(r5, r11)
            if (r12 != r0) goto L55
            goto L78
        L55:
            float r12 = r8.a
            r1 = 0
            int r12 = (r12 > r1 ? 1 : (r12 == r1 ? 0 : -1))
            if (r12 != 0) goto L3e
            androidx.compose.animation.core.K r12 = new androidx.compose.animation.core.K
            r1 = 0
            r12.<init>(r9, r1)
            androidx.datastore.core.t r12 = androidx.compose.runtime.C0776c.F(r12)
            androidx.compose.animation.core.L r1 = new androidx.compose.animation.core.L
            r4 = 0
            r1.<init>(r3, r4)
            r11.l = r9
            r11.j = r8
            r11.k = r3
            java.lang.Object r12 = kotlinx.coroutines.flow.e0.q(r12, r1, r11)
            if (r12 != r0) goto L3e
        L78:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.core.M.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
