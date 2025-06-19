package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ t k;
    public final /* synthetic */ int l;
    public final /* synthetic */ boolean m;
    public final /* synthetic */ boolean n;
    public final /* synthetic */ ArrayList o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(t tVar, int i, boolean z, boolean z2, ArrayList arrayList, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = tVar;
        this.l = i;
        this.m = z;
        this.n = z2;
        this.o = arrayList;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        ArrayList arrayList = this.o;
        return new l(this.k, this.l, this.m, this.n, arrayList, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0079  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.j
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t r4 = r12.k
            r2 = 1
            if (r1 == 0) goto L17
            if (r1 != r2) goto Lf
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L29
        Lf:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L17:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            androidx.work.impl.model.c r13 = r4.c
            io.reactivex.rxjava3.internal.operators.single.g r13 = r13.t()
            r12.j = r2
            java.lang.Object r13 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r13, r12)
            if (r13 != r0) goto L29
            return r0
        L29:
            java.lang.String r0 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r13, r0)
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            boolean r13 = r13.booleanValue()
            r4.getClass()
            r0 = 80
            int r1 = r12.l
            boolean r2 = r12.m
            if (r1 > r0) goto L79
            java.util.ArrayList r0 = r12.o
            int r1 = r0.size()
            r3 = 4
            if (r1 < r3) goto L79
            com.quizlet.quizletandroid.ui.studymodes.testmode.models.i r1 = new com.quizlet.quizletandroid.ui.studymodes.testmode.models.i
            com.quizlet.uicommon.ui.common.util.a r10 = new com.quizlet.uicommon.ui.common.util.a
            int r3 = r0.size()
            r10.<init>()
            boolean r5 = r12.n
            r10.a = r5
            r10.b = r3
            r10.c = r13
            com.quizlet.uicommon.ui.common.util.b r11 = new com.quizlet.uicommon.ui.common.util.b
            r11.<init>(r2, r13)
            com.quizlet.features.setpage.header.ui.g r13 = new com.quizlet.features.setpage.header.ui.g
            r2 = 28
            r13.<init>(r2, r4, r0)
            androidx.compose.ui.scrollcapture.k r2 = new androidx.compose.ui.scrollcapture.k
            java.lang.String r7 = "handleNextStep(Lcom/quizlet/uicommon/ui/common/util/StudyModeNextStep;Ljava/util/List;)V"
            r8 = 0
            r3 = 1
            java.lang.Class<com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t> r5 = com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t.class
            java.lang.String r6 = "handleNextStep"
            r9 = 1
            r2.<init>(r3, r4, r5, r6, r7, r8, r9)
            r1.<init>(r10, r11, r13, r2)
            goto La2
        L79:
            com.quizlet.quizletandroid.ui.studymodes.testmode.models.i r1 = new com.quizlet.quizletandroid.ui.studymodes.testmode.models.i
            com.quizlet.uicommon.ui.common.util.b r0 = new com.quizlet.uicommon.ui.common.util.b
            r0.<init>(r2, r13)
            com.quizlet.uicommon.ui.common.util.c r13 = com.quizlet.uicommon.ui.common.util.c.a
            androidx.compose.ui.scrollcapture.k r2 = new androidx.compose.ui.scrollcapture.k
            java.lang.String r7 = "handleNextStep(Lcom/quizlet/uicommon/ui/common/util/StudyModeNextStep;Ljava/util/List;)V"
            r8 = 0
            r3 = 1
            java.lang.Class<com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t> r5 = com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t.class
            java.lang.String r6 = "handleNextStep"
            r9 = 2
            r2.<init>(r3, r4, r5, r6, r7, r8, r9)
            r10 = r2
            androidx.compose.ui.scrollcapture.k r2 = new androidx.compose.ui.scrollcapture.k
            java.lang.String r7 = "handleNextStep(Lcom/quizlet/uicommon/ui/common/util/StudyModeNextStep;Ljava/util/List;)V"
            r8 = 0
            r3 = 1
            java.lang.Class<com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t> r5 = com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t.class
            java.lang.String r6 = "handleNextStep"
            r9 = 3
            r2.<init>(r3, r4, r5, r6, r7, r8, r9)
            r1.<init>(r0, r13, r10, r2)
        La2:
            kotlinx.coroutines.flow.s0 r13 = r4.i
            java.lang.Object r0 = r13.getValue()
            r2 = r0
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.b r2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4760b) r2
            com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.b r2 = new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.b
            java.util.List r3 = kotlin.collections.A.b(r1)
            r2.<init>(r3)
            boolean r13 = r13.k(r0, r2)
            if (r13 == 0) goto La2
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.l.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
