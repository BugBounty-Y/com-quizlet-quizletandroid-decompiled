package com.quizlet.features.folders.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public N k;
    public com.quizlet.data.interactor.folderstudymaterial.g l;
    public int m;
    public final /* synthetic */ N n;
    public final /* synthetic */ com.quizlet.data.interactor.folderstudymaterial.g o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(N n, com.quizlet.data.interactor.folderstudymaterial.g gVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = n;
        this.o = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new K(this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:33:0x00d3, code lost:
    
        if (r3.emit(r4, r18) == r1) goto L34;
     */
    /* JADX WARN: Removed duplicated region for block: B:26:0x00b3  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00ba  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r19) {
        /*
            Method dump skipped, instructions count: 217
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.K.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
