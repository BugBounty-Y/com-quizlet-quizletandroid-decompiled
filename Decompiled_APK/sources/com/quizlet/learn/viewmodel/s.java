package com.quizlet.learn.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public G j;
    public int k;
    public final /* synthetic */ G l;
    public final /* synthetic */ com.quizlet.features.infra.basestudy.data.models.dataproviders.a m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(G g, com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = g;
        this.m = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new s(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((s) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:213:0x05db  */
    /* JADX WARN: Removed duplicated region for block: B:216:0x05e5  */
    /* JADX WARN: Removed duplicated region for block: B:223:0x067c  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00cd  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0108  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0159  */
    /* JADX WARN: Type inference failed for: r21v0 */
    /* JADX WARN: Type inference failed for: r21v1 */
    /* JADX WARN: Type inference failed for: r21v3 */
    /* JADX WARN: Type inference failed for: r21v4 */
    /* JADX WARN: Type inference failed for: r21v5 */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r32) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1666
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.learn.viewmodel.s.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
