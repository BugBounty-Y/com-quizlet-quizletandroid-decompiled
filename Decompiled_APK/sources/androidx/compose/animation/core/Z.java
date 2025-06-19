package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.c j;
    public C0247i0 k;
    public int l;
    public final /* synthetic */ C0247i0 m;
    public final /* synthetic */ Object n;
    public final /* synthetic */ E0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Z(C0247i0 c0247i0, E0 e0, Object obj, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = c0247i0;
        this.n = obj;
        this.o = e0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new Z(this.m, this.o, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Z) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:78:0x0183, code lost:
    
        if (androidx.compose.animation.core.C0247i0.W(r14, r24) != r0) goto L80;
     */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00cb A[PHI: r16
  0x00cb: PHI (r16v6 long) = (r16v4 long), (r16v5 long), (r16v9 long) binds: [B:26:0x0092, B:40:0x00c7, B:13:0x0031] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00d9  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r25) {
        /*
            Method dump skipped, instructions count: 401
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.core.Z.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
