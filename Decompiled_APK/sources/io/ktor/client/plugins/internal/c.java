package io.ktor.client.plugins.internal;

import io.ktor.utils.io.B;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ J l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(J j, h hVar) {
        super(2, hVar);
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        c cVar = new c(this.l, hVar);
        cVar.k = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((B) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0089, code lost:
    
        if (r8 == r0) goto L27;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) throws java.lang.Throwable {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            r2 = 0
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L22
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L8c
        L12:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1a:
            java.lang.Object r1 = r7.k
            io.ktor.utils.io.B r1 = (io.ktor.utils.io.B) r1
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L6c
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r7.k
            r1 = r8
            io.ktor.utils.io.B r1 = (io.ktor.utils.io.B) r1
            kotlin.jvm.internal.J r8 = r7.l
            java.lang.Object r8 = r8.a
            kotlin.jvm.internal.Intrinsics.d(r8)
            io.ktor.client.plugins.internal.b r8 = (io.ktor.client.plugins.internal.b) r8
            r7.k = r1
            r7.j = r4
            io.ktor.utils.io.A r4 = r8.b
            java.lang.String r5 = "writerJob"
            if (r4 == 0) goto L8f
            io.ktor.utils.io.u r6 = io.ktor.utils.io.w.a
            java.lang.String r6 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r6)
            java.lang.Object r4 = r4.c
            kotlinx.coroutines.y0 r4 = (kotlinx.coroutines.y0) r4
            boolean r4 = r4.d0()
            if (r4 != 0) goto L63
            io.ktor.utils.io.A r4 = r8.b
            if (r4 == 0) goto L5f
            io.ktor.client.plugins.internal.SaveBodyAbandonedReadException r5 = new io.ktor.client.plugins.internal.SaveBodyAbandonedReadException
            r5.<init>()
            java.lang.Object r4 = r4.b
            io.ktor.utils.io.k r4 = (io.ktor.utils.io.k) r4
            r4.b(r5)
            goto L63
        L5f:
            kotlin.jvm.internal.Intrinsics.m(r5)
            throw r2
        L63:
            kotlinx.coroutines.r r8 = r8.a
            java.lang.Object r8 = r8.w(r7)
            if (r8 != r0) goto L6c
            goto L8b
        L6c:
            byte[] r8 = (byte[]) r8
            io.ktor.utils.io.t r1 = r1.a
            r7.k = r2
            r7.j = r3
            io.ktor.utils.io.u r2 = io.ktor.utils.io.w.a
            int r2 = r8.length
            io.ktor.utils.io.k r1 = (io.ktor.utils.io.k) r1
            kotlinx.io.a r3 = r1.i()
            r3.j(r2, r8)
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3243q7.f(r1, r7)
            if (r8 != r0) goto L87
            goto L89
        L87:
            kotlin.Unit r8 = kotlin.Unit.a
        L89:
            if (r8 != r0) goto L8c
        L8b:
            return r0
        L8c:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        L8f:
            kotlin.jvm.internal.Intrinsics.m(r5)
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.internal.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
