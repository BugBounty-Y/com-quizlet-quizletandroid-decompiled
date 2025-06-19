package androidx.datastore.core;

import java.io.Serializable;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class G extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public Serializable j;
    public int k;
    public final /* synthetic */ kotlin.jvm.internal.J l;
    public final /* synthetic */ P m;
    public final /* synthetic */ kotlin.jvm.internal.H n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(kotlin.jvm.internal.J j, P p, kotlin.jvm.internal.H h, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.l = j;
        this.m = p;
        this.n = h;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new G(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((G) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x006a, code lost:
    
        if (r9 != r0) goto L30;
     */
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
            kotlin.jvm.internal.H r2 = r8.n
            kotlin.jvm.internal.J r3 = r8.l
            r4 = 3
            r5 = 2
            androidx.datastore.core.P r6 = r8.m
            r7 = 1
            if (r1 == 0) goto L36
            if (r1 == r7) goto L2e
            if (r1 == r5) goto L26
            if (r1 != r4) goto L1e
            java.io.Serializable r0 = r8.j
            r2 = r0
            kotlin.jvm.internal.H r2 = (kotlin.jvm.internal.H) r2
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L6d
        L1e:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L26:
            java.io.Serializable r1 = r8.j
            kotlin.jvm.internal.H r1 = (kotlin.jvm.internal.H) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: androidx.datastore.core.CorruptionException -> L60
            goto L57
        L2e:
            java.io.Serializable r1 = r8.j
            kotlin.jvm.internal.J r1 = (kotlin.jvm.internal.J) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: androidx.datastore.core.CorruptionException -> L60
            goto L45
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r8.j = r3     // Catch: androidx.datastore.core.CorruptionException -> L60
            r8.k = r7     // Catch: androidx.datastore.core.CorruptionException -> L60
            java.lang.Object r9 = r6.i(r8)     // Catch: androidx.datastore.core.CorruptionException -> L60
            if (r9 != r0) goto L44
            goto L6c
        L44:
            r1 = r3
        L45:
            r1.a = r9     // Catch: androidx.datastore.core.CorruptionException -> L60
            androidx.datastore.core.k0 r9 = r6.g()     // Catch: androidx.datastore.core.CorruptionException -> L60
            r8.j = r2     // Catch: androidx.datastore.core.CorruptionException -> L60
            r8.k = r5     // Catch: androidx.datastore.core.CorruptionException -> L60
            java.lang.Integer r9 = r9.a()     // Catch: androidx.datastore.core.CorruptionException -> L60
            if (r9 != r0) goto L56
            goto L6c
        L56:
            r1 = r2
        L57:
            java.lang.Number r9 = (java.lang.Number) r9     // Catch: androidx.datastore.core.CorruptionException -> L60
            int r9 = r9.intValue()     // Catch: androidx.datastore.core.CorruptionException -> L60
            r1.a = r9     // Catch: androidx.datastore.core.CorruptionException -> L60
            goto L75
        L60:
            java.lang.Object r9 = r3.a
            r8.j = r2
            r8.k = r4
            java.lang.Object r9 = r6.j(r9, r7, r8)
            if (r9 != r0) goto L6d
        L6c:
            return r0
        L6d:
            java.lang.Number r9 = (java.lang.Number) r9
            int r9 = r9.intValue()
            r2.a = r9
        L75:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.G.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
