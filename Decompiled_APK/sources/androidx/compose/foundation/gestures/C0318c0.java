package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.c0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0318c0 extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ CoroutineContext m;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.h n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C0318c0(CoroutineContext coroutineContext, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = coroutineContext;
        this.n = (kotlin.coroutines.jvm.internal.h) function2;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.h, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0318c0 c0318c0 = new C0318c0(this.m, this.n, hVar);
        c0318c0.l = obj;
        return c0318c0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0318c0) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0057, code lost:
    
        if (r9 != r0) goto L12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x006c, code lost:
    
        if (r9 == r0) goto L34;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0041 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r1v21 */
    /* JADX WARN: Type inference failed for: r1v3, types: [androidx.compose.ui.input.pointer.z, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r1v7, types: [kotlin.coroutines.jvm.internal.h, kotlin.jvm.functions.Function2] */
    /* JADX WARN: Type inference failed for: r1v9 */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:26:0x0057 -> B:12:0x0028). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:33:0x006c -> B:12:0x0028). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.k
            kotlin.coroutines.CoroutineContext r2 = r8.m
            r3 = 3
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L34
            if (r1 == r5) goto L2c
            if (r1 == r4) goto L21
            if (r1 != r3) goto L19
            java.lang.Object r1 = r8.l
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L28
        L19:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L21:
            java.lang.Object r1 = r8.l
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.util.concurrent.CancellationException -> L2a
        L28:
            r9 = r1
            goto L3b
        L2a:
            r9 = move-exception
            goto L5e
        L2c:
            java.lang.Object r1 = r8.l
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.util.concurrent.CancellationException -> L2a
            goto L4f
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r8.l
            androidx.compose.ui.input.pointer.z r9 = (androidx.compose.ui.input.pointer.z) r9
        L3b:
            boolean r1 = kotlinx.coroutines.E.w(r2)
            if (r1 == 0) goto L70
            kotlin.coroutines.jvm.internal.h r1 = r8.n     // Catch: java.util.concurrent.CancellationException -> L5a
            r8.l = r9     // Catch: java.util.concurrent.CancellationException -> L5a
            r8.k = r5     // Catch: java.util.concurrent.CancellationException -> L5a
            java.lang.Object r1 = r1.invoke(r9, r8)     // Catch: java.util.concurrent.CancellationException -> L5a
            if (r1 != r0) goto L4e
            goto L6e
        L4e:
            r1 = r9
        L4f:
            r8.l = r1     // Catch: java.util.concurrent.CancellationException -> L2a
            r8.k = r4     // Catch: java.util.concurrent.CancellationException -> L2a
            java.lang.Object r9 = androidx.compose.foundation.gestures.AbstractC0349s0.c(r1, r8)     // Catch: java.util.concurrent.CancellationException -> L2a
            if (r9 != r0) goto L28
            goto L6e
        L5a:
            r1 = move-exception
            r7 = r1
            r1 = r9
            r9 = r7
        L5e:
            boolean r6 = kotlinx.coroutines.E.w(r2)
            if (r6 == 0) goto L6f
            r8.l = r1
            r8.k = r3
            java.lang.Object r9 = androidx.compose.foundation.gestures.AbstractC0349s0.c(r1, r8)
            if (r9 != r0) goto L28
        L6e:
            return r0
        L6f:
            throw r9
        L70:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.C0318c0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
