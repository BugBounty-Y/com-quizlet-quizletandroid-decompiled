package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class H extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new H(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((H) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x0044, code lost:
    
        if (r6 == r0) goto L22;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) throws java.lang.Throwable {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            r2 = 2
            r3 = 1
            androidx.datastore.core.P r4 = r5.k
            if (r1 == 0) goto L20
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L47
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Throwable -> L1e
            goto L3d
        L1e:
            r6 = move-exception
            goto L4a
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.webkit.internal.p r6 = r4.h
            androidx.datastore.core.l0 r6 = r6.q()
            boolean r6 = r6 instanceof androidx.datastore.core.a0
            if (r6 == 0) goto L34
            androidx.webkit.internal.p r6 = r4.h
            androidx.datastore.core.l0 r6 = r6.q()
            return r6
        L34:
            r5.j = r3     // Catch: java.lang.Throwable -> L1e
            java.lang.Object r6 = r4.h(r5)     // Catch: java.lang.Throwable -> L1e
            if (r6 != r0) goto L3d
            goto L46
        L3d:
            r5.j = r2
            r6 = 0
            java.lang.Object r6 = androidx.datastore.core.P.e(r4, r6, r5)
            if (r6 != r0) goto L47
        L46:
            return r0
        L47:
            androidx.datastore.core.l0 r6 = (androidx.datastore.core.l0) r6
            return r6
        L4a:
            androidx.datastore.core.c0 r0 = new androidx.datastore.core.c0
            r1 = -1
            r0.<init>(r1, r6)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.H.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
