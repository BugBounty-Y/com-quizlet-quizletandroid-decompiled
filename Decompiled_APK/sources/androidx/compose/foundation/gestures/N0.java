package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class N0 extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public long k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ androidx.compose.ui.input.pointer.n n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N0(androidx.compose.ui.input.pointer.n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        N0 n0 = new N0(this.n, hVar);
        n0.m = obj;
        return n0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((N0) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /*  JADX ERROR: JadxOverflowException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxOverflowException: Regions count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        */
    /* JADX WARN: Removed duplicated region for block: B:11:0x003f A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0048 A[RETURN] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:10:0x003d -> B:12:0x0040). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.l
            r2 = 1
            if (r1 == 0) goto L1b
            if (r1 != r2) goto L13
            long r3 = r7.k
            java.lang.Object r1 = r7.m
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L40
        L13:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r7.m
            androidx.compose.ui.input.pointer.z r8 = (androidx.compose.ui.input.pointer.z) r8
            androidx.compose.ui.input.pointer.n r1 = r7.n
            long r3 = r1.b
            androidx.compose.ui.platform.Y0 r1 = r8.e()
            r1.getClass()
            r5 = 40
            long r5 = r5 + r3
            r1 = r8
            r3 = r5
        L32:
            r7.m = r1
            r7.k = r3
            r7.l = r2
            r8 = 3
            java.lang.Object r8 = androidx.compose.foundation.gestures.k1.c(r1, r7, r8)
            if (r8 != r0) goto L40
            return r0
        L40:
            androidx.compose.ui.input.pointer.n r8 = (androidx.compose.ui.input.pointer.n) r8
            long r5 = r8.b
            int r5 = (r5 > r3 ? 1 : (r5 == r3 ? 0 : -1))
            if (r5 < 0) goto L32
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.N0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
