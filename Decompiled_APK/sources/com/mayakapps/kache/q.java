package com.mayakapps.kache;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public kotlinx.coroutines.sync.c k;
    public u l;
    public String m;
    public int n;
    public final /* synthetic */ Function2 o;
    public final /* synthetic */ String p;
    public final /* synthetic */ u q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(Function2 function2, String str, u uVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = function2;
        this.p = str;
        this.q = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x005f, code lost:
    
        if (r0 == r2) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00c5, code lost:
    
        if (r8.d(r19) != r2) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00e7, code lost:
    
        if (r8.d(r19) == r2) goto L55;
     */
    /* JADX WARN: Removed duplicated region for block: B:32:0x008c A[Catch: all -> 0x00ac, TryCatch #3 {all -> 0x00ac, blocks: (B:30:0x007e, B:32:0x008c, B:34:0x0093, B:36:0x00a2), top: B:67:0x007e, outer: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0091  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00a2 A[Catch: all -> 0x00ac, TRY_LEAVE, TryCatch #3 {all -> 0x00ac, blocks: (B:30:0x007e, B:32:0x008c, B:34:0x0093, B:36:0x00a2), top: B:67:0x007e, outer: #2 }] */
    /* JADX WARN: Type inference failed for: r6v3, types: [kotlin.jvm.functions.d, kotlin.jvm.internal.r] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r20) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 251
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.q.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
