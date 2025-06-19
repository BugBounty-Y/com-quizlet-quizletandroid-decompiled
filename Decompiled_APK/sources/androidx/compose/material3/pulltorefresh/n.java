package androidx.compose.material3.pulltorefresh;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ o k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(o oVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new n(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0028, code lost:
    
        if (r5.P0(r4) == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0031, code lost:
    
        if (r5.Q0(r4) == r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0033, code lost:
    
        return r0;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r5) {
        /*
            r4 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r4.j
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L19
            if (r1 == r3) goto L15
            if (r1 != r2) goto Ld
            goto L15
        Ld:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L15:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L34
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            androidx.compose.material3.pulltorefresh.o r5 = r4.k
            boolean r1 = r5.p
            if (r1 != 0) goto L2b
            r4.j = r3
            java.lang.Object r5 = r5.P0(r4)
            if (r5 != r0) goto L34
            goto L33
        L2b:
            r4.j = r2
            java.lang.Object r5 = r5.Q0(r4)
            if (r5 != r0) goto L34
        L33:
            return r0
        L34:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.pulltorefresh.n.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
