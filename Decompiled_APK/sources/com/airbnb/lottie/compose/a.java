package com.airbnb.lottie.compose;

import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ h k;
    public final /* synthetic */ com.airbnb.lottie.h l;
    public final /* synthetic */ int m;
    public final /* synthetic */ float n;
    public final /* synthetic */ l o;
    public final /* synthetic */ InterfaceC0773a0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(h hVar, com.airbnb.lottie.h hVar2, int i, float f, l lVar, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar3) {
        super(2, hVar3);
        this.k = hVar;
        this.l = hVar2;
        this.m = i;
        this.n = f;
        this.o = lVar;
        this.p = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.k, this.l, this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:41:0x00ec, code lost:
    
        if (r13 == r0) goto L42;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            Method dump skipped, instructions count: 242
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.compose.a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
