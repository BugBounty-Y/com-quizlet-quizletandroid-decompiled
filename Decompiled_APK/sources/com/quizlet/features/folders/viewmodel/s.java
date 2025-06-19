package com.quizlet.features.folders.viewmodel;

import com.quizlet.features.folders.data.Q0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public N j;
    public Q0 k;
    public Object l;
    public Object m;
    public Q0 n;
    public N o;
    public int p;
    public /* synthetic */ Object q;
    public final /* synthetic */ N r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.r = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        s sVar = new s(this.r, hVar);
        sVar.q = obj;
        return sVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((s) create(new kotlin.r(((kotlin.r) obj).a), (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x00f1 A[LOOP:0: B:27:0x00f1->B:42:?, LOOP_START] */
    /* JADX WARN: Removed duplicated region for block: B:38:0x012e  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:24:0x00cc -> B:25:0x00d0). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r20) {
        /*
            Method dump skipped, instructions count: 313
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.s.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
