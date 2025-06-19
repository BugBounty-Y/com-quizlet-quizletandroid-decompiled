package androidx.compose.ui.platform;

import android.view.View;
import androidx.compose.runtime.C0832v0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class l1 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ kotlin.jvm.internal.J l;
    public final /* synthetic */ C0832v0 m;
    public final /* synthetic */ androidx.lifecycle.J n;
    public final /* synthetic */ m1 o;
    public final /* synthetic */ View p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l1(kotlin.jvm.internal.J j, C0832v0 c0832v0, androidx.lifecycle.J j2, m1 m1Var, View view, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = j;
        this.m = c0832v0;
        this.n = j2;
        this.o = m1Var;
        this.p = view;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        l1 l1Var = new l1(this.l, this.m, this.n, this.o, this.p, hVar);
        l1Var.k = obj;
        return l1Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l1) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0081  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) throws java.lang.Throwable {
        /*
            r10 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r10.j
            androidx.lifecycle.J r2 = r10.n
            r3 = 0
            androidx.compose.ui.platform.m1 r4 = r10.o
            r5 = 1
            if (r1 == 0) goto L21
            if (r1 != r5) goto L19
            java.lang.Object r0 = r10.k
            kotlinx.coroutines.j0 r0 = (kotlinx.coroutines.InterfaceC5025j0) r0
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Throwable -> L16
            goto L6a
        L16:
            r11 = move-exception
            goto L7f
        L19:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            java.lang.Object r11 = r10.k
            kotlinx.coroutines.C r11 = (kotlinx.coroutines.C) r11
            kotlin.jvm.internal.J r1 = r10.l     // Catch: java.lang.Throwable -> L58
            java.lang.Object r1 = r1.a     // Catch: java.lang.Throwable -> L58
            androidx.compose.ui.platform.z0 r1 = (androidx.compose.ui.platform.C0980z0) r1     // Catch: java.lang.Throwable -> L58
            if (r1 == 0) goto L5b
            android.view.View r6 = r10.p     // Catch: java.lang.Throwable -> L58
            android.content.Context r6 = r6.getContext()     // Catch: java.lang.Throwable -> L58
            android.content.Context r6 = r6.getApplicationContext()     // Catch: java.lang.Throwable -> L58
            kotlinx.coroutines.flow.q0 r6 = androidx.compose.ui.platform.p1.a(r6)     // Catch: java.lang.Throwable -> L58
            java.lang.Object r7 = r6.getValue()     // Catch: java.lang.Throwable -> L58
            java.lang.Number r7 = (java.lang.Number) r7     // Catch: java.lang.Throwable -> L58
            float r7 = r7.floatValue()     // Catch: java.lang.Throwable -> L58
            androidx.compose.runtime.F0 r8 = r1.a     // Catch: java.lang.Throwable -> L58
            r8.j(r7)     // Catch: java.lang.Throwable -> L58
            androidx.compose.ui.platform.k1 r7 = new androidx.compose.ui.platform.k1     // Catch: java.lang.Throwable -> L58
            r7.<init>(r6, r1, r3)     // Catch: java.lang.Throwable -> L58
            r1 = 3
            kotlinx.coroutines.y0 r11 = kotlinx.coroutines.E.A(r11, r3, r3, r7, r1)     // Catch: java.lang.Throwable -> L58
            goto L5c
        L58:
            r11 = move-exception
            r0 = r3
            goto L7f
        L5b:
            r11 = r3
        L5c:
            androidx.compose.runtime.v0 r1 = r10.m     // Catch: java.lang.Throwable -> L7d
            r10.k = r11     // Catch: java.lang.Throwable -> L7d
            r10.j = r5     // Catch: java.lang.Throwable -> L7d
            java.lang.Object r1 = r1.H(r10)     // Catch: java.lang.Throwable -> L7d
            if (r1 != r0) goto L69
            return r0
        L69:
            r0 = r11
        L6a:
            if (r0 == 0) goto L6f
            r0.j(r3)
        L6f:
            androidx.lifecycle.C r11 = r2.getLifecycle()
            r11.b(r4)
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        L79:
            r9 = r0
            r0 = r11
            r11 = r9
            goto L7f
        L7d:
            r0 = move-exception
            goto L79
        L7f:
            if (r0 == 0) goto L84
            r0.j(r3)
        L84:
            androidx.lifecycle.C r0 = r2.getLifecycle()
            r0.b(r4)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.l1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
