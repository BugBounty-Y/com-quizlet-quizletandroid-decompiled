package com.quizlet.features.notes.detail.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ v k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(v vVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = vVar;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new p(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((p) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x006f, code lost:
    
        if (r5.G(null, r13) == r0) goto L17;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r14) {
        /*
            r13 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r13.j
            r2 = 1
            boolean r3 = r13.l
            r4 = 2
            com.quizlet.features.notes.detail.viewmodels.v r5 = r13.k
            if (r1 == 0) goto L20
            if (r1 == r2) goto L1c
            if (r1 != r4) goto L14
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L72
        L14:
            java.lang.IllegalStateException r14 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r14.<init>(r0)
            throw r14
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L34
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.google.android.material.floatingactionbutton.c r14 = r5.o
            java.lang.String r1 = r5.C()
            r6 = r3 ^ 1
            r13.j = r2
            java.lang.Object r14 = r14.m(r1, r13, r6)
            if (r14 != r0) goto L34
            goto L71
        L34:
            com.quizlet.features.notes.logging.f r14 = r5.f
            java.lang.String r1 = r5.C()
            r14.getClass()
            com.quizlet.eventlogger.model.NotesEventLog$Companion r2 = com.quizlet.eventlogger.model.NotesEventLog.b
            com.quizlet.generated.enums.a0 r6 = com.quizlet.generated.enums.EnumC4465a0.PRIVACY_SETTINGS_UPDATED
            java.lang.String r6 = r6.a()
            com.quizlet.features.notes.logging.b r7 = new com.quizlet.features.notes.logging.b
            r7.<init>(r3, r1)
            com.quizlet.generated.enums.n r1 = com.quizlet.features.notes.logging.a.c
            r2.getClass()
            com.quizlet.eventlogger.model.NotesEventLog r1 = com.quizlet.eventlogger.model.NotesEventLog.Companion.a(r1, r6, r7)
            r14.a(r1)
            com.quizlet.data.model.NotesToValueInfo r6 = r5.v
            r14 = 0
            if (r6 == 0) goto L75
            r10 = 0
            r11 = 0
            boolean r7 = r13.l
            r8 = 0
            r9 = 0
            r12 = 2045(0x7fd, float:2.866E-42)
            com.quizlet.data.model.NotesToValueInfo r1 = com.quizlet.data.model.NotesToValueInfo.a(r6, r7, r8, r9, r10, r11, r12)
            r5.v = r1
            r13.j = r4
            java.lang.Object r14 = r5.G(r14, r13)
            if (r14 != r0) goto L72
        L71:
            return r0
        L72:
            kotlin.Unit r14 = kotlin.Unit.a
            return r14
        L75:
            java.lang.String r0 = "magicNotes"
            kotlin.jvm.internal.Intrinsics.m(r0)
            throw r14
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.detail.viewmodels.p.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
