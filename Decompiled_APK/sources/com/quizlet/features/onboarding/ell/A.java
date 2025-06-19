package com.quizlet.features.onboarding.ell;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class A extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ l k;
    public final /* synthetic */ B l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(l lVar, B b, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = lVar;
        this.l = b;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new A(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((A) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x004c, code lost:
    
        if (com.quizlet.features.onboarding.ell.B.A(r6, true, r12, r11) == r0) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00d5, code lost:
    
        if (com.quizlet.features.onboarding.ell.B.A(r6, true, r12, r11) != r0) goto L57;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0166, code lost:
    
        if (com.quizlet.features.onboarding.ell.B.A(r6, false, r12, r11) == r0) goto L53;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 394
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.onboarding.ell.A.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
