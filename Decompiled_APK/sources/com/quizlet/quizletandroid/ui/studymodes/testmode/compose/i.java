package com.quizlet.quizletandroid.ui.studymodes.testmode.compose;

import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ com.quizlet.features.infra.ui.feedback.sound.soundeffect.e m;
    public final /* synthetic */ InterfaceC0773a0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(boolean z, com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVar, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = z;
        this.m = eVar;
        this.n = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        i iVar = new i(this.l, this.m, this.n, hVar);
        iVar.k = obj;
        return iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.k) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0043, code lost:
    
        if (r4.a(r6, r5) == r0) goto L19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0059, code lost:
    
        if (r4.a(r6, r5) == r0) goto L19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x005b, code lost:
    
        return r0;
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
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L19
            if (r1 == r3) goto L15
            if (r1 != r2) goto Ld
            goto L15
        Ld:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L15:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L5c
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r5.k
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.k r6 = (com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.k) r6
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.i r1 = com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4767i.a
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r6, r1)
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.e r4 = r5.m
            if (r1 == 0) goto L46
            boolean r6 = r5.l
            r6 = r6 ^ r3
            float r1 = com.quizlet.quizletandroid.ui.studymodes.testmode.compose.m.a
            java.lang.Boolean r6 = java.lang.Boolean.valueOf(r6)
            androidx.compose.runtime.a0 r1 = r5.n
            r1.setValue(r6)
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.b r6 = com.quizlet.features.infra.ui.feedback.sound.soundeffect.b.c
            r5.j = r3
            r4.getClass()
            java.lang.Object r6 = r4.a(r6, r5)
            if (r6 != r0) goto L5c
            goto L5b
        L46:
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.j r1 = com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.j.a
            boolean r6 = kotlin.jvm.internal.Intrinsics.b(r6, r1)
            if (r6 == 0) goto L5f
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.b r6 = com.quizlet.features.infra.ui.feedback.sound.soundeffect.b.b
            r5.j = r2
            r4.getClass()
            java.lang.Object r6 = r4.a(r6, r5)
            if (r6 != r0) goto L5c
        L5b:
            return r0
        L5c:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L5f:
            kotlin.NoWhenBranchMatchedException r6 = new kotlin.NoWhenBranchMatchedException
            r6.<init>()
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.compose.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
