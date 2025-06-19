package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ G k;
    public final /* synthetic */ ArrayList l;
    public final /* synthetic */ List m;
    public final /* synthetic */ List n;
    public final /* synthetic */ boolean o;
    public final /* synthetic */ com.quizlet.features.infra.basestudy.data.models.dataproviders.a p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public z(G g, ArrayList arrayList, List list, List list2, boolean z, com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
        this.l = arrayList;
        this.m = list;
        this.n = list2;
        this.o = z;
        this.p = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new z(this.k, this.l, this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((z) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:104:0x020b  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x021d  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x0220  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x022a  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x028b  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0206 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00a5  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x019e  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x01af  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x01e0  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x01e3  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x01f6  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 657
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.z.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
