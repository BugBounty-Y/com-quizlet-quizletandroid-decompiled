package androidx.compose.foundation.text.input.internal;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ InterfaceC5025j0 k;
    public final /* synthetic */ n l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(InterfaceC5025j0 interfaceC5025j0, n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = interfaceC5025j0;
        this.l = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new l(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((l) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    /* JADX WARN: Path cross not found for [B:18:0x0031, B:21:0x003a], limit reached: 27 */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0049  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x004a A[Catch: all -> 0x0018, TRY_LEAVE, TryCatch #0 {all -> 0x0018, blocks: (B:7:0x0014, B:21:0x003a, B:24:0x004a, B:13:0x0022), top: B:29:0x000c }] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:25:0x0055 -> B:21:0x003a). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.j
            r2 = 0
            r3 = 500(0x1f4, double:2.47E-321)
            r5 = 3
            r6 = 2
            r7 = 1
            androidx.compose.foundation.text.input.internal.n r8 = r9.l
            if (r1 == 0) goto L2a
            if (r1 == r7) goto L26
            if (r1 == r6) goto L22
            if (r1 != r5) goto L1a
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L18
            goto L3a
        L18:
            r10 = move-exception
            goto L58
        L1a:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L18
            goto L4a
        L26:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L3a
        L2a:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlinx.coroutines.j0 r10 = r9.k
            if (r10 == 0) goto L3a
            r9.j = r7
            java.lang.Object r10 = kotlinx.coroutines.E.k(r10, r9)
            if (r10 != r0) goto L3a
            goto L57
        L3a:
            androidx.compose.runtime.F0 r10 = r8.b     // Catch: java.lang.Throwable -> L18
            r1 = 1065353216(0x3f800000, float:1.0)
            r10.j(r1)     // Catch: java.lang.Throwable -> L18
            r9.j = r6     // Catch: java.lang.Throwable -> L18
            java.lang.Object r10 = kotlinx.coroutines.E.n(r3, r9)     // Catch: java.lang.Throwable -> L18
            if (r10 != r0) goto L4a
            goto L57
        L4a:
            androidx.compose.runtime.F0 r10 = r8.b     // Catch: java.lang.Throwable -> L18
            r10.j(r2)     // Catch: java.lang.Throwable -> L18
            r9.j = r5     // Catch: java.lang.Throwable -> L18
            java.lang.Object r10 = kotlinx.coroutines.E.n(r3, r9)     // Catch: java.lang.Throwable -> L18
            if (r10 != r0) goto L3a
        L57:
            return r0
        L58:
            androidx.compose.runtime.F0 r0 = r8.b
            r0.j(r2)
            throw r10
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.input.internal.l.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
