package com.quizlet.features.folders.viewmodel;

import com.quizlet.generated.enums.y1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.folders.viewmodel.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4327h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public final /* synthetic */ N l;
    public final /* synthetic */ String m;
    public final /* synthetic */ y1 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4327h(N n, String str, y1 y1Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = n;
        this.m = str;
        this.n = y1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4327h(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4327h) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:63:0x0142, code lost:
    
        if (r2 == r1) goto L64;
     */
    /* JADX WARN: Removed duplicated region for block: B:50:0x010c  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r23) {
        /*
            Method dump skipped, instructions count: 328
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.C4327h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
