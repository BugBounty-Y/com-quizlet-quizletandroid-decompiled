package androidx.compose.material3;

import androidx.compose.ui.platform.InterfaceC0938e;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class I3 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ L3 k;
    public final /* synthetic */ InterfaceC0938e l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I3(L3 l3, InterfaceC0938e interfaceC0938e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = l3;
        this.l = interfaceC0938e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new I3(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((I3) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0086 A[RETURN] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) {
        /*
            r11 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r11.j
            androidx.compose.material3.L3 r2 = r11.k
            r3 = 1
            if (r1 == 0) goto L18
            if (r1 != r3) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L87
        L10:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            if (r2 == 0) goto L8a
            androidx.compose.material3.V3 r12 = r2.a
            int r1 = r12.getDuration()
            java.lang.String r12 = r12.b()
            if (r12 == 0) goto L2b
            r12 = r3
            goto L2c
        L2b:
            r12 = 0
        L2c:
            int r1 = androidx.camera.camera2.internal.AbstractC0147y.k(r1)
            r4 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
            if (r1 == 0) goto L47
            if (r1 == r3) goto L44
            r6 = 2
            if (r1 != r6) goto L3e
            r6 = r4
            goto L49
        L3e:
            kotlin.NoWhenBranchMatchedException r12 = new kotlin.NoWhenBranchMatchedException
            r12.<init>()
            throw r12
        L44:
            r6 = 10000(0x2710, double:4.9407E-320)
            goto L49
        L47:
            r6 = 4000(0xfa0, double:1.9763E-320)
        L49:
            androidx.compose.ui.platform.e r1 = r11.l
            if (r1 != 0) goto L4e
            goto L7d
        L4e:
            androidx.compose.ui.platform.f r1 = (androidx.compose.ui.platform.C0940f) r1
            r8 = 2147483647(0x7fffffff, double:1.060997895E-314)
            int r8 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1))
            if (r8 < 0) goto L58
            goto L7d
        L58:
            if (r12 == 0) goto L5c
            r8 = 7
            goto L5d
        L5c:
            r8 = 3
        L5d:
            int r9 = android.os.Build.VERSION.SDK_INT
            r10 = 29
            android.view.accessibility.AccessibilityManager r1 = r1.a
            if (r9 < r10) goto L74
            androidx.compose.ui.platform.g0 r12 = androidx.compose.ui.platform.C0943g0.a
            int r6 = (int) r6
            int r12 = r12.a(r1, r6, r8)
            r1 = 2147483647(0x7fffffff, float:NaN)
            if (r12 != r1) goto L72
            goto L7e
        L72:
            long r4 = (long) r12
            goto L7e
        L74:
            if (r12 == 0) goto L7d
            boolean r12 = r1.isTouchExplorationEnabled()
            if (r12 == 0) goto L7d
            goto L7e
        L7d:
            r4 = r6
        L7e:
            r11.j = r3
            java.lang.Object r12 = kotlinx.coroutines.E.n(r4, r11)
            if (r12 != r0) goto L87
            return r0
        L87:
            r2.a()
        L8a:
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.I3.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
