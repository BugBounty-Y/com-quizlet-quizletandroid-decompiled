package coil3.compose;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public j j;
    public int k;
    public final /* synthetic */ j l;
    public final /* synthetic */ c m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(j jVar, c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = jVar;
        this.m = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0037, code lost:
    
        if (r6 == r0) goto L18;
     */
    /* JADX WARN: Removed duplicated region for block: B:22:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0072  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.k
            r2 = 2
            coil3.compose.j r3 = r5.l
            r4 = 1
            if (r1 == 0) goto L20
            if (r1 == r4) goto L1c
            if (r1 != r2) goto L14
            coil3.compose.j r0 = r5.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L54
        L14:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L3a
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            coil3.compose.m r6 = r3.q
            coil3.compose.c r1 = r5.m
            if (r6 == 0) goto L3d
            coil3.request.g r2 = r1.b
            coil3.request.g r2 = coil3.compose.j.j(r3, r2, r4)
            coil3.m r1 = r1.a
            r5.k = r4
            java.lang.Object r6 = r6.a(r1, r2, r5)
            if (r6 != r0) goto L3a
            goto L52
        L3a:
            coil3.compose.h r6 = (coil3.compose.h) r6
            goto L8e
        L3d:
            coil3.request.g r6 = r1.b
            r4 = 0
            coil3.request.g r6 = coil3.compose.j.j(r3, r6, r4)
            coil3.m r1 = r1.a
            r5.j = r3
            r5.k = r2
            coil3.u r1 = (coil3.u) r1
            java.lang.Object r6 = r1.b(r6, r5)
            if (r6 != r0) goto L53
        L52:
            return r0
        L53:
            r0 = r3
        L54:
            coil3.request.j r6 = (coil3.request.j) r6
            r0.getClass()
            boolean r1 = r6 instanceof coil3.request.o
            if (r1 == 0) goto L72
            coil3.compose.g r1 = new coil3.compose.g
            coil3.request.o r6 = (coil3.request.o) r6
            coil3.j r2 = r6.a
            coil3.request.g r4 = r6.b
            android.content.Context r4 = r4.a
            int r0 = r0.p
            androidx.compose.ui.graphics.painter.b r0 = com.google.android.gms.internal.mlkit_vision_camera.q3.a(r2, r4, r0)
            r1.<init>(r0, r6)
        L70:
            r6 = r1
            goto L8e
        L72:
            boolean r1 = r6 instanceof coil3.request.c
            if (r1 == 0) goto L94
            coil3.compose.e r1 = new coil3.compose.e
            coil3.request.c r6 = (coil3.request.c) r6
            coil3.j r2 = r6.a
            if (r2 == 0) goto L89
            coil3.request.g r4 = r6.b
            android.content.Context r4 = r4.a
            int r0 = r0.p
            androidx.compose.ui.graphics.painter.b r0 = com.google.android.gms.internal.mlkit_vision_camera.q3.a(r2, r4, r0)
            goto L8a
        L89:
            r0 = 0
        L8a:
            r1.<init>(r0, r6)
            goto L70
        L8e:
            coil3.compose.j.k(r3, r6)
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L94:
            kotlin.NoWhenBranchMatchedException r6 = new kotlin.NoWhenBranchMatchedException
            r6.<init>()
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.compose.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
