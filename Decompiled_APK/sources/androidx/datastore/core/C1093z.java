package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.datastore.core.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1093z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1093z(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1093z(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1093z) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x004c, code lost:
    
        if (r6.b(r1, r5) == r0) goto L18;
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
            androidx.datastore.core.P r2 = r5.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4f
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L35
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r5.j = r4
            com.quizlet.data.repository.explanations.exercise.b r6 = r2.i
            java.lang.Object r6 = r6.b
            kotlinx.coroutines.r r6 = (kotlinx.coroutines.r) r6
            java.lang.Object r6 = r6.w(r5)
            if (r6 != r0) goto L30
            goto L32
        L30:
            kotlin.Unit r6 = kotlin.Unit.a
        L32:
            if (r6 != r0) goto L35
            goto L4e
        L35:
            androidx.datastore.core.k0 r6 = r2.g()
            androidx.datastore.core.t r6 = r6.c
            r1 = -1
            kotlinx.coroutines.flow.i r6 = kotlinx.coroutines.flow.e0.f(r6, r1)
            androidx.compose.foundation.text.input.internal.b r1 = new androidx.compose.foundation.text.input.internal.b
            r4 = 2
            r1.<init>(r2, r4)
            r5.j = r3
            java.lang.Object r6 = r6.b(r1, r5)
            if (r6 != r0) goto L4f
        L4e:
            return r0
        L4f:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.C1093z.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
