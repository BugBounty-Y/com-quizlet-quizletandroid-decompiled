package androidx.compose.foundation.gestures.snapping;

import androidx.compose.animation.core.C0253l0;
import androidx.compose.animation.core.C0276z;
import androidx.compose.foundation.gestures.AbstractC0349s0;
import androidx.compose.foundation.gestures.C0321e;
import androidx.compose.foundation.gestures.C0338m0;
import androidx.compose.foundation.gestures.G0;
import androidx.compose.foundation.gestures.InterfaceC0314a0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h implements InterfaceC0314a0 {
    public final m a;
    public final C0276z b;
    public final C0253l0 c;
    public final C0338m0 d = AbstractC0349s0.b;

    public h(m mVar, C0276z c0276z, C0253l0 c0253l0) {
        this.a = mVar;
        this.b = c0276z;
        this.c = c0253l0;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0018  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(androidx.compose.foundation.gestures.snapping.h r5, androidx.compose.foundation.gestures.G0 r6, float r7, float r8, androidx.compose.foundation.gestures.snapping.d r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r0 = 7
            r5.getClass()
            boolean r1 = r10 instanceof androidx.compose.foundation.gestures.snapping.g
            if (r1 == 0) goto L18
            r1 = r10
            androidx.compose.foundation.gestures.snapping.g r1 = (androidx.compose.foundation.gestures.snapping.g) r1
            int r2 = r1.l
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L18
            int r2 = r2 - r3
            r1.l = r2
        L16:
            r10 = r1
            goto L1e
        L18:
            androidx.compose.foundation.gestures.snapping.g r1 = new androidx.compose.foundation.gestures.snapping.g
            r1.<init>(r5, r10)
            goto L16
        L1e:
            java.lang.Object r1 = r10.j
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r10.l
            r4 = 1
            if (r3 == 0) goto L35
            if (r3 != r4) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r1)
            goto L8b
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r1)
            float r1 = java.lang.Math.abs(r7)
            r3 = 0
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 != 0) goto L42
            goto L4a
        L42:
            float r1 = java.lang.Math.abs(r8)
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 != 0) goto L51
        L4a:
            r5 = 28
            androidx.compose.animation.core.o r5 = androidx.compose.animation.core.AbstractC0240f.b(r7, r8, r5)
            return r5
        L51:
            r10.l = r4
            androidx.compose.animation.core.L0 r1 = androidx.compose.animation.core.M0.a
            androidx.compose.animation.core.z r1 = r5.b
            androidx.compose.animation.core.F r4 = r1.a
            float r3 = r4.r(r3, r8)
            float r3 = java.lang.Math.abs(r3)
            float r4 = java.lang.Math.abs(r7)
            int r3 = (r3 > r4 ? 1 : (r3 == r4 ? 0 : -1))
            if (r3 < 0) goto L70
            androidx.appcompat.app.L r5 = new androidx.appcompat.app.L
            r5.<init>(r1, r0)
        L6e:
            r0 = r7
            goto L79
        L70:
            com.quizlet.data.repository.school.membership.a r1 = new com.quizlet.data.repository.school.membership.a
            androidx.compose.animation.core.l0 r5 = r5.c
            r1.<init>(r5, r0)
            r5 = r1
            goto L6e
        L79:
            java.lang.Float r7 = new java.lang.Float
            r7.<init>(r0)
            r0 = r8
            java.lang.Float r8 = new java.lang.Float
            r8.<init>(r0)
            java.lang.Object r1 = r5.B(r6, r7, r8, r9, r10)
            if (r1 != r2) goto L8b
            return r2
        L8b:
            androidx.compose.foundation.gestures.snapping.a r1 = (androidx.compose.foundation.gestures.snapping.a) r1
            androidx.compose.animation.core.o r5 = r1.b
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.snapping.h.b(androidx.compose.foundation.gestures.snapping.h, androidx.compose.foundation.gestures.G0, float, float, androidx.compose.foundation.gestures.snapping.d, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.compose.foundation.gestures.InterfaceC0314a0
    public Object a(G0 g0, float f, kotlin.coroutines.h hVar) {
        return d(g0, f, C0321e.f, (kotlin.coroutines.jvm.internal.c) hVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(androidx.compose.foundation.gestures.G0 r11, float r12, kotlin.jvm.functions.Function1 r13, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r0 = r14 instanceof androidx.compose.foundation.gestures.snapping.c
            if (r0 == 0) goto L13
            r0 = r14
            androidx.compose.foundation.gestures.snapping.c r0 = (androidx.compose.foundation.gestures.snapping.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.foundation.gestures.snapping.c r0 = new androidx.compose.foundation.gestures.snapping.c
            r0.<init>(r10, r14)
        L18:
            java.lang.Object r14 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            kotlin.jvm.functions.Function1 r13 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L4c
        L29:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            androidx.compose.foundation.gestures.m0 r14 = r10.d
            androidx.compose.foundation.gestures.snapping.e r4 = new androidx.compose.foundation.gestures.snapping.e
            r9 = 0
            r5 = r10
            r8 = r11
            r6 = r12
            r7 = r13
            r4.<init>(r5, r6, r7, r8, r9)
            r0.j = r7
            r0.m = r3
            java.lang.Object r14 = kotlinx.coroutines.E.J(r14, r4, r0)
            if (r14 != r1) goto L4b
            return r1
        L4b:
            r13 = r7
        L4c:
            androidx.compose.foundation.gestures.snapping.a r14 = (androidx.compose.foundation.gestures.snapping.a) r14
            java.lang.Float r11 = new java.lang.Float
            r12 = 0
            r11.<init>(r12)
            r13.invoke(r11)
            return r14
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.snapping.h.c(androidx.compose.foundation.gestures.G0, float, kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(androidx.compose.foundation.gestures.G0 r5, float r6, kotlin.jvm.functions.Function1 r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r8 instanceof androidx.compose.foundation.gestures.snapping.f
            if (r0 == 0) goto L13
            r0 = r8
            androidx.compose.foundation.gestures.snapping.f r0 = (androidx.compose.foundation.gestures.snapping.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.compose.foundation.gestures.snapping.f r0 = new androidx.compose.foundation.gestures.snapping.f
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L3b
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.l = r3
            java.lang.Object r8 = r4.c(r5, r6, r7, r0)
            if (r8 != r1) goto L3b
            return r1
        L3b:
            androidx.compose.foundation.gestures.snapping.a r8 = (androidx.compose.foundation.gestures.snapping.a) r8
            java.lang.Float r5 = r8.a
            float r5 = r5.floatValue()
            r6 = 0
            int r5 = (r5 > r6 ? 1 : (r5 == r6 ? 0 : -1))
            if (r5 != 0) goto L49
            goto L55
        L49:
            androidx.compose.animation.core.o r5 = r8.b
            java.lang.Object r5 = r5.a()
            java.lang.Number r5 = (java.lang.Number) r5
            float r6 = r5.floatValue()
        L55:
            java.lang.Float r5 = new java.lang.Float
            r5.<init>(r6)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.snapping.h.d(androidx.compose.foundation.gestures.G0, float, kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return hVar.c.equals(this.c) && Intrinsics.b(hVar.b, this.b) && Intrinsics.b(hVar.a, this.a);
    }

    public final int hashCode() {
        return this.a.hashCode() + ((this.b.hashCode() + (this.c.hashCode() * 31)) * 31);
    }
}
