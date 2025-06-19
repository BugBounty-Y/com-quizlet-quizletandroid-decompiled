package com.quizlet.features.questiontypes.truefalse;

import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public c k;
    public String l;
    public int m;
    public final /* synthetic */ DefaultQuestionSectionData n;
    public final /* synthetic */ l o;
    public final /* synthetic */ c p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(DefaultQuestionSectionData defaultQuestionSectionData, l lVar, c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = defaultQuestionSectionData;
        this.o = lVar;
        this.p = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:41:0x0099, code lost:
    
        if (com.quizlet.features.questiontypes.truefalse.l.A(r5, false, r1) != r0) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x00bf, code lost:
    
        if (com.quizlet.features.questiontypes.truefalse.l.A(r5, false, r1) == r0) goto L59;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:39:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00d1  */
    /* JADX WARN: Type inference failed for: r1v0, types: [int] */
    /* JADX WARN: Type inference failed for: r5v0 */
    /* JADX WARN: Type inference failed for: r5v2 */
    /* JADX WARN: Type inference failed for: r5v4 */
    /* JADX WARN: Type inference failed for: r5v9 */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 214
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.truefalse.k.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
