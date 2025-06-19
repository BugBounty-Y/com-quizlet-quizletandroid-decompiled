package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ TestStudyModeConfig l;
    public final /* synthetic */ G m;
    public final /* synthetic */ DBSession n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(TestStudyModeConfig testStudyModeConfig, G g, DBSession dBSession, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = testStudyModeConfig;
        this.m = g;
        this.n = dBSession;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        y yVar = new y(this.l, this.m, this.n, hVar);
        yVar.k = obj;
        return yVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((y) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x005a, code lost:
    
        if (r2 == r1) goto L17;
     */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00b2  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r18) {
        /*
            Method dump skipped, instructions count: 418
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.y.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
