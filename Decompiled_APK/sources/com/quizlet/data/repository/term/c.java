package com.quizlet.data.repository.term;

import com.quizlet.data.model.J0;
import com.quizlet.data.model.N;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class c extends i implements Function2 {
    public Object j;
    public N k;
    public long l;
    public int m;
    public final /* synthetic */ g n;
    public final /* synthetic */ long o;
    public final /* synthetic */ J0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(g gVar, long j, J0 j0, h hVar) {
        super(2, hVar);
        this.n = gVar;
        this.o = j;
        this.p = j0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:40:0x0171, code lost:
    
        if (r3 != r2) goto L42;
     */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0184  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r21) {
        /*
            Method dump skipped, instructions count: 401
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.term.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
