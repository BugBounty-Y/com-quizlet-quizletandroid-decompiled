package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x003e, code lost:
    
        if (r6.emit(r1, r5) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i r2 = r5.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L41
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L34
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.features.infra.basestudy.manager.f r6 = r2.r
            com.quizlet.features.infra.studysetting.managers.a r6 = r6.g()
            com.quizlet.features.infra.studysetting.data.QuestionSettings r6 = r6.c()
            r5.j = r4
            java.lang.Object r6 = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i.A(r2, r6, r5)
            if (r6 != r0) goto L34
            goto L40
        L34:
            kotlinx.coroutines.flow.d0 r6 = r2.q
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.k r1 = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.k.a
            r5.j = r3
            java.lang.Object r6 = r6.emit(r1, r5)
            if (r6 != r0) goto L41
        L40:
            return r0
        L41:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.g.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
