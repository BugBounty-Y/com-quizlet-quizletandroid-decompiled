package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class f1 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.appcompat.app.L l;
    public final /* synthetic */ int m;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public f1(androidx.appcompat.app.L l, int i, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = l;
        this.m = i;
        this.n = (kotlin.coroutines.jvm.internal.i) function1;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        f1 f1Var = new f1(this.l, this.m, this.n, hVar);
        f1Var.k = obj;
        return f1Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f1) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x0087, code lost:
    
        if (r9.a(r1, r8) != r0) goto L37;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r1v1, types: [kotlinx.coroutines.j0] */
    /* JADX WARN: Type inference failed for: r1v14 */
    /* JADX WARN: Type inference failed for: r1v15 */
    /* JADX WARN: Type inference failed for: r1v9, types: [kotlinx.coroutines.j0] */
    /* JADX WARN: Type inference failed for: r3v2, types: [com.google.android.gms.internal.ads.rn] */
    /* JADX WARN: Type inference failed for: r9v12, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    /* JADX WARN: Type inference failed for: r9v15, types: [com.google.android.gms.internal.ads.rn] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) throws java.lang.Throwable {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            r2 = 4
            r3 = 3
            r4 = 2
            r5 = 1
            androidx.appcompat.app.L r6 = r8.l
            if (r1 == 0) goto L3c
            if (r1 == r5) goto L34
            if (r1 == r4) goto L2a
            if (r1 == r3) goto L25
            if (r1 == r2) goto L1c
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1c:
            java.lang.Object r0 = r8.k
            java.lang.Throwable r0 = (java.lang.Throwable) r0
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L9a
        L25:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L9b
        L2a:
            java.lang.Object r1 = r8.k
            kotlinx.coroutines.j0 r1 = (kotlinx.coroutines.InterfaceC5025j0) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L32
            goto L7a
        L32:
            r9 = move-exception
            goto L8a
        L34:
            java.lang.Object r1 = r8.k
            kotlinx.coroutines.j0 r1 = (kotlinx.coroutines.InterfaceC5025j0) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L65
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r8.k
            kotlinx.coroutines.C r9 = (kotlinx.coroutines.C) r9
            kotlin.coroutines.CoroutineContext r9 = r9.getCoroutineContext()
            kotlinx.coroutines.i0 r1 = kotlinx.coroutines.C5023i0.a
            kotlin.coroutines.CoroutineContext$Element r9 = r9.get(r1)
            if (r9 == 0) goto L9e
            kotlinx.coroutines.j0 r9 = (kotlinx.coroutines.InterfaceC5025j0) r9
            java.lang.Object r1 = r6.b
            com.google.android.gms.internal.ads.rn r1 = (com.google.android.gms.internal.ads.C2580rn) r1
            r8.k = r9
            r8.j = r5
            int r5 = r8.m
            java.lang.Object r1 = r1.b(r5, r9, r8)
            if (r1 != r0) goto L62
            goto L98
        L62:
            r7 = r1
            r1 = r9
            r9 = r7
        L65:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 == 0) goto L9b
            kotlin.coroutines.jvm.internal.i r9 = r8.n     // Catch: java.lang.Throwable -> L32
            r8.k = r1     // Catch: java.lang.Throwable -> L32
            r8.j = r4     // Catch: java.lang.Throwable -> L32
            java.lang.Object r9 = r9.invoke(r8)     // Catch: java.lang.Throwable -> L32
            if (r9 != r0) goto L7a
            goto L98
        L7a:
            java.lang.Object r9 = r6.b
            com.google.android.gms.internal.ads.rn r9 = (com.google.android.gms.internal.ads.C2580rn) r9
            r2 = 0
            r8.k = r2
            r8.j = r3
            java.lang.Object r9 = r9.a(r1, r8)
            if (r9 != r0) goto L9b
            goto L98
        L8a:
            java.lang.Object r3 = r6.b
            com.google.android.gms.internal.ads.rn r3 = (com.google.android.gms.internal.ads.C2580rn) r3
            r8.k = r9
            r8.j = r2
            java.lang.Object r1 = r3.a(r1, r8)
            if (r1 != r0) goto L99
        L98:
            return r0
        L99:
            r0 = r9
        L9a:
            throw r0
        L9b:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L9e:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "Internal error. coroutineScope should've created a job."
            r9.<init>(r0)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.f1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
