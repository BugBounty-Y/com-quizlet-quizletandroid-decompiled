package com.google.firebase.sessions;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;

/* renamed from: com.google.firebase.sessions.o, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3993o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C3994p k;
    public final /* synthetic */ CoroutineContext l;
    public final /* synthetic */ d0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3993o(C3994p c3994p, CoroutineContext coroutineContext, d0 d0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c3994p;
        this.l = coroutineContext;
        this.m = d0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C3993o(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C3993o) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x0063, code lost:
    
        if (r10.b(r9) == r1) goto L25;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            Method dump skipped, instructions count: 296
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.sessions.C3993o.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
