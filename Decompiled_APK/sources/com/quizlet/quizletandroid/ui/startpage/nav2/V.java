package com.quizlet.quizletandroid.ui.startpage.nav2;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class V extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ int k;
    public final /* synthetic */ Y l;
    public final /* synthetic */ long m;
    public final /* synthetic */ com.quizlet.generated.enums.F n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(int i, Y y, long j, com.quizlet.generated.enums.F f, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = i;
        this.l = y;
        this.m = j;
        this.n = f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new V(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((V) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:116:0x01e3, code lost:
    
        if (com.quizlet.quizletandroid.ui.startpage.nav2.Y.C(r6, r2, r18) == r1) goto L120;
     */
    /* JADX WARN: Code restructure failed: missing block: B:119:0x020c, code lost:
    
        if (com.quizlet.quizletandroid.ui.startpage.nav2.Y.C(r6, r3, r18) == r1) goto L120;
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x020e, code lost:
    
        return r1;
     */
    /* JADX WARN: Removed duplicated region for block: B:113:0x01c6  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x0223  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0103  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0107  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0130  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0142  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0145  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r19) {
        /*
            Method dump skipped, instructions count: 550
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.V.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
