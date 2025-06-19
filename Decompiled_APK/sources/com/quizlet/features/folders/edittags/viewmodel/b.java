package com.quizlet.features.folders.edittags.viewmodel;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, h hVar) {
        super(2, hVar);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x007a, code lost:
    
        if (r6.emit(r11, r10) != r0) goto L28;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) {
        /*
            r10 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r10.j
            com.quizlet.features.folders.edittags.viewmodel.c r2 = r10.k
            r3 = 3
            r4 = 2
            r5 = 1
            kotlinx.coroutines.flow.d0 r6 = r2.h
            kotlinx.coroutines.flow.s0 r7 = r2.g
            if (r1 == 0) goto L29
            if (r1 == r5) goto L25
            if (r1 == r4) goto L21
            if (r1 != r3) goto L19
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L7d
        L19:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Exception -> L72
            goto L5a
        L25:
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Exception -> L72
            goto L4f
        L29:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            com.quizlet.data.repository.qclass.c r11 = r2.b     // Catch: java.lang.Exception -> L72
            java.lang.Long r1 = r2.i     // Catch: java.lang.Exception -> L72
            if (r1 == 0) goto L6a
            long r8 = r1.longValue()     // Catch: java.lang.Exception -> L72
            java.lang.Object r1 = r7.getValue()     // Catch: java.lang.Exception -> L72
            com.quizlet.features.folders.edittags.data.g r1 = (com.quizlet.features.folders.edittags.data.g) r1     // Catch: java.lang.Exception -> L72
            java.lang.String r1 = r1.a     // Catch: java.lang.Exception -> L72
            java.lang.CharSequence r1 = kotlin.text.StringsKt.g0(r1)     // Catch: java.lang.Exception -> L72
            java.lang.String r1 = r1.toString()     // Catch: java.lang.Exception -> L72
            r10.j = r5     // Catch: java.lang.Exception -> L72
            java.lang.Object r11 = r11.n(r8, r1, r10)     // Catch: java.lang.Exception -> L72
            if (r11 != r0) goto L4f
            goto L7c
        L4f:
            java.lang.Boolean r11 = java.lang.Boolean.TRUE     // Catch: java.lang.Exception -> L72
            r10.j = r4     // Catch: java.lang.Exception -> L72
            java.lang.Object r11 = r6.emit(r11, r10)     // Catch: java.lang.Exception -> L72
            if (r11 != r0) goto L5a
            goto L7c
        L5a:
            com.quizlet.eventlogger.features.folder.FolderLogger r11 = r2.e     // Catch: java.lang.Exception -> L72
            long r1 = r2.f     // Catch: java.lang.Exception -> L72
            java.lang.Object r4 = r7.getValue()     // Catch: java.lang.Exception -> L72
            com.quizlet.features.folders.edittags.data.g r4 = (com.quizlet.features.folders.edittags.data.g) r4     // Catch: java.lang.Exception -> L72
            java.lang.String r4 = r4.a     // Catch: java.lang.Exception -> L72
            r11.r(r1, r4)     // Catch: java.lang.Exception -> L72
            goto L7d
        L6a:
            java.lang.String r11 = "Required value was null."
            java.lang.IllegalArgumentException r1 = new java.lang.IllegalArgumentException     // Catch: java.lang.Exception -> L72
            r1.<init>(r11)     // Catch: java.lang.Exception -> L72
            throw r1     // Catch: java.lang.Exception -> L72
        L72:
            java.lang.Boolean r11 = java.lang.Boolean.FALSE
            r10.j = r3
            java.lang.Object r11 = r6.emit(r11, r10)
            if (r11 != r0) goto L7d
        L7c:
            return r0
        L7d:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.edittags.viewmodel.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
