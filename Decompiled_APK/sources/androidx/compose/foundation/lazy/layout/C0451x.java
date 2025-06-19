package androidx.compose.foundation.lazy.layout;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.lazy.layout.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0451x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ boolean k;
    public final /* synthetic */ E l;
    public final /* synthetic */ androidx.compose.animation.core.D m;
    public final /* synthetic */ androidx.compose.ui.graphics.layer.b n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0451x(boolean z, E e, androidx.compose.animation.core.D d, androidx.compose.ui.graphics.layer.b bVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = z;
        this.l = e;
        this.m = d;
        this.n = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0451x(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0451x) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x0054, code lost:
    
        if (androidx.compose.animation.core.C0238e.c(r6, r7, r8, r9, r12, 4) == r0) goto L22;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            r12 = this;
            r1 = 0
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r2 = r12.j
            r3 = 2
            r4 = 1
            androidx.compose.foundation.lazy.layout.E r5 = r12.l
            if (r2 == 0) goto L22
            if (r2 == r4) goto L1e
            if (r2 != r3) goto L16
            androidx.glance.appwidget.protobuf.Z.e(r13)     // Catch: java.lang.Throwable -> L13
            goto L57
        L13:
            r0 = move-exception
            r13 = r0
            goto L5f
        L16:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r13)     // Catch: java.lang.Throwable -> L13
            goto L3a
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            boolean r13 = r12.k     // Catch: java.lang.Throwable -> L13
            if (r13 == 0) goto L3a
            androidx.compose.animation.core.e r13 = r5.p     // Catch: java.lang.Throwable -> L13
            java.lang.Float r2 = new java.lang.Float     // Catch: java.lang.Throwable -> L13
            r6 = 0
            r2.<init>(r6)     // Catch: java.lang.Throwable -> L13
            r12.j = r4     // Catch: java.lang.Throwable -> L13
            java.lang.Object r13 = r13.f(r2, r12)     // Catch: java.lang.Throwable -> L13
            if (r13 != r0) goto L3a
            goto L56
        L3a:
            androidx.compose.animation.core.e r6 = r5.p     // Catch: java.lang.Throwable -> L13
            java.lang.Float r7 = new java.lang.Float     // Catch: java.lang.Throwable -> L13
            r13 = 1065353216(0x3f800000, float:1.0)
            r7.<init>(r13)     // Catch: java.lang.Throwable -> L13
            androidx.compose.animation.core.D r8 = r12.m     // Catch: java.lang.Throwable -> L13
            androidx.compose.foundation.lazy.layout.w r9 = new androidx.compose.foundation.lazy.layout.w     // Catch: java.lang.Throwable -> L13
            androidx.compose.ui.graphics.layer.b r13 = r12.n     // Catch: java.lang.Throwable -> L13
            r9.<init>(r13, r5, r1)     // Catch: java.lang.Throwable -> L13
            r12.j = r3     // Catch: java.lang.Throwable -> L13
            r11 = 4
            r10 = r12
            java.lang.Object r13 = androidx.compose.animation.core.C0238e.c(r6, r7, r8, r9, r10, r11)     // Catch: java.lang.Throwable -> L13
            if (r13 != r0) goto L57
        L56:
            return r0
        L57:
            int r13 = androidx.compose.foundation.lazy.layout.E.t
            r5.d(r1)
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        L5f:
            int r0 = androidx.compose.foundation.lazy.layout.E.t
            r5.d(r1)
            throw r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.layout.C0451x.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
