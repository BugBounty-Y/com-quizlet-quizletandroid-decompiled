package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class E0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ N k;
    public final /* synthetic */ androidx.paging.compose.c l;
    public final /* synthetic */ C1351y0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E0(N n, androidx.paging.compose.c cVar, C1351y0 c1351y0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = n;
        this.l = cVar;
        this.m = c1351y0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new E0(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x0054, code lost:
    
        if (androidx.paging.compose.c.a(r0, r1, r2, r4, true, r5, r6, r7, r10) == r9) goto L78;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0092, code lost:
    
        if (kotlin.Unit.a != r9) goto L27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x0188, code lost:
    
        if (kotlin.Unit.a != r9) goto L79;
     */
    /* JADX WARN: Removed duplicated region for block: B:19:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0132  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x014d  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x016b  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x01cb  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x01d0  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x01de A[LOOP:0: B:89:0x01d8->B:91:0x01de, LOOP_END] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) {
        /*
            Method dump skipped, instructions count: 510
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.E0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
