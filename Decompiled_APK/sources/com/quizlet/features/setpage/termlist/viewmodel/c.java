package com.quizlet.features.setpage.termlist.viewmodel;

import androidx.compose.material3.internal.H;
import androidx.paging.J0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public H j;
    public J0 k;
    public com.quizlet.features.flashcards.helpers.d l;
    public int m;
    public final /* synthetic */ j n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(j jVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x00e6, code lost:
    
        if (kotlinx.coroutines.flow.e0.i(r1, r2, r22) == r5) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r23) {
        /*
            Method dump skipped, instructions count: 236
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.setpage.termlist.viewmodel.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
