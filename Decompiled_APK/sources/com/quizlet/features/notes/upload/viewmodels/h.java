package com.quizlet.features.notes.upload.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public k j;
    public int k;
    public final /* synthetic */ Boolean l;
    public final /* synthetic */ k m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(Boolean bool, k kVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = bool;
        this.m = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0044, code lost:
    
        if (r13 == r0) goto L20;
     */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0055  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.k
            r2 = 2
            com.quizlet.features.notes.upload.viewmodels.k r3 = r12.m
            r4 = 1
            if (r1 == 0) goto L20
            if (r1 == r4) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L47
        L12:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L1a:
            com.quizlet.features.notes.upload.viewmodels.k r1 = r12.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L39
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Boolean r13 = r12.l
            if (r13 == 0) goto L2d
            boolean r13 = r13.booleanValue()
        L2b:
            r10 = r13
            goto L53
        L2d:
            r12.j = r3
            r12.k = r4
            java.lang.Object r13 = r3.A(r12)
            if (r13 != r0) goto L38
            goto L46
        L38:
            r1 = r3
        L39:
            com.quizlet.data.model.w0 r13 = (com.quizlet.data.model.InterfaceC4176w0) r13
            r5 = 0
            r12.j = r5
            r12.k = r2
            java.lang.Object r13 = com.quizlet.features.notes.upload.viewmodels.k.K(r1, r13, r12)
            if (r13 != r0) goto L47
        L46:
            return r0
        L47:
            java.lang.Number r13 = (java.lang.Number) r13
            int r13 = r13.intValue()
            if (r13 <= 0) goto L51
            r10 = r4
            goto L53
        L51:
            r13 = 0
            goto L2b
        L53:
            if (r10 == 0) goto L68
            com.quizlet.features.notes.a r13 = r3.t
            r13.getClass()
            com.quizlet.eventlogger.model.ScanNotesMeteringToastEventLog r0 = new com.quizlet.eventlogger.model.ScanNotesMeteringToastEventLog
            java.lang.String r1 = "notes_toast"
            java.lang.String r2 = "notes_to_value_headsup_impression"
            r0.<init>(r1, r2)
            com.quizlet.eventlogger.EventLogger r13 = r13.a
            r13.l(r0)
        L68:
            kotlinx.coroutines.flow.s0 r13 = r3.x
        L6a:
            java.lang.Object r0 = r13.getValue()
            r1 = r0
            com.quizlet.features.notes.upload.states.h r1 = (com.quizlet.features.notes.upload.states.h) r1
            com.quizlet.features.notes.upload.states.a r5 = new com.quizlet.features.notes.upload.states.a
            int r7 = r3.m
            int r8 = r3.n
            boolean r1 = r3.D()
            r9 = r1 ^ 1
            com.quizlet.features.infra.models.folders.AddMaterialFolderData r11 = r3.C()
            com.quizlet.data.model.m2 r6 = r3.l
            r5.<init>(r6, r7, r8, r9, r10, r11)
            boolean r0 = r13.k(r0, r5)
            if (r0 == 0) goto L6a
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.upload.viewmodels.h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
