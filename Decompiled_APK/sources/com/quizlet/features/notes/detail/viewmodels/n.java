package com.quizlet.features.notes.detail.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ v k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(v vVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = vVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new n(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x007c, code lost:
    
        if (r8.G(null, r16) == r1) goto L19;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r17) throws java.lang.Throwable {
        /*
            r16 = this;
            r0 = r16
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.j
            r3 = 0
            java.lang.String r4 = r0.l
            java.lang.String r5 = "magicNotes"
            r6 = 2
            r7 = 1
            com.quizlet.features.notes.detail.viewmodels.v r8 = r0.k
            if (r2 == 0) goto L27
            if (r2 == r7) goto L21
            if (r2 != r6) goto L19
            androidx.glance.appwidget.protobuf.Z.e(r17)
            goto L7f
        L19:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r17)
            r2 = r17
            goto L3b
        L27:
            androidx.glance.appwidget.protobuf.Z.e(r17)
            com.lyft.android.scissors.b r2 = r8.n
            com.quizlet.data.model.NotesToValueInfo r9 = r8.v
            if (r9 == 0) goto L86
            r0.j = r7
            com.quizlet.data.model.TitleInfo r7 = r9.c
            java.lang.Object r2 = r2.m(r7, r4, r0)
            if (r2 != r1) goto L3b
            goto L7e
        L3b:
            r11 = r2
            com.quizlet.data.model.TitleInfo r11 = (com.quizlet.data.model.TitleInfo) r11
            com.quizlet.features.notes.logging.f r2 = r8.f
            java.lang.String r7 = r8.C()
            r2.getClass()
            java.lang.String r9 = "newTitle"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r9)
            com.quizlet.eventlogger.model.NotesEventLog$Companion r9 = com.quizlet.eventlogger.model.NotesEventLog.b
            com.quizlet.generated.enums.a0 r10 = com.quizlet.generated.enums.EnumC4465a0.TITLE_EDITED
            java.lang.String r10 = r10.a()
            com.braze.ui.e r12 = new com.braze.ui.e
            r13 = 6
            r12.<init>(r13, r7, r4)
            com.quizlet.generated.enums.n r4 = com.quizlet.features.notes.logging.a.c
            r9.getClass()
            com.quizlet.eventlogger.model.NotesEventLog r4 = com.quizlet.eventlogger.model.NotesEventLog.Companion.a(r4, r10, r12)
            r2.a(r4)
            com.quizlet.data.model.NotesToValueInfo r9 = r8.v
            if (r9 == 0) goto L82
            r13 = 0
            r14 = 0
            r10 = 0
            r12 = 0
            r15 = 2043(0x7fb, float:2.863E-42)
            com.quizlet.data.model.NotesToValueInfo r2 = com.quizlet.data.model.NotesToValueInfo.a(r9, r10, r11, r12, r13, r14, r15)
            r8.v = r2
            r0.j = r6
            java.lang.Object r2 = r8.G(r3, r0)
            if (r2 != r1) goto L7f
        L7e:
            return r1
        L7f:
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        L82:
            kotlin.jvm.internal.Intrinsics.m(r5)
            throw r3
        L86:
            kotlin.jvm.internal.Intrinsics.m(r5)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.detail.viewmodels.n.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
