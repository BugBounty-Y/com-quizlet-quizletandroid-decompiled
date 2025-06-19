package androidx.glance.session;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class w extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public Object j;
    public int k;
    public final /* synthetic */ SessionWorker l;
    public final /* synthetic */ K m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(SessionWorker sessionWorker, K k, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.l = sessionWorker;
        this.m = k;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new w(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((w) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:38:0x00c0, code lost:
    
        if (kotlinx.coroutines.E.J(r15, r0, r14) != r1) goto L40;
     */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00e5 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:61:? A[RETURN, SYNTHETIC] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r15) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 231
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.session.w.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
