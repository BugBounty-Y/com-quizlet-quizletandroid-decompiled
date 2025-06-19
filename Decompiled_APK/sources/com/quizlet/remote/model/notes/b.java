package com.quizlet.remote.model.notes;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, h hVar) {
        super(2, hVar);
        this.k = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x0047, code lost:
    
        if (r6 == r0) goto L22;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) throws java.lang.Throwable {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            com.quizlet.remote.model.notes.e r2 = r5.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Exception -> L52
            goto L4a
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Exception -> L52
            goto L2f
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r2.b     // Catch: java.lang.Exception -> L52
            com.quizlet.remote.service.q r6 = (com.quizlet.remote.service.q) r6     // Catch: java.lang.Exception -> L52
            r5.j = r4     // Catch: java.lang.Exception -> L52
            r1 = 6
            java.lang.Object r6 = r6.b(r1, r5)     // Catch: java.lang.Exception -> L52
            if (r6 != r0) goto L2f
            goto L49
        L2f:
            com.quizlet.remote.model.base.ApiThreeWrapper r6 = (com.quizlet.remote.model.base.ApiThreeWrapper) r6     // Catch: java.lang.Exception -> L52
            com.quizlet.remote.model.base.ApiResponse r6 = r6.a()     // Catch: java.lang.Exception -> L52
            com.quizlet.remote.model.notes.RemoteNotesResponse r6 = (com.quizlet.remote.model.notes.RemoteNotesResponse) r6     // Catch: java.lang.Exception -> L52
            if (r6 == 0) goto L4f
            com.quizlet.remote.model.notes.StudyNoteModel r6 = r6.d     // Catch: java.lang.Exception -> L52
            if (r6 == 0) goto L4f
            java.lang.Object r1 = r2.e     // Catch: java.lang.Exception -> L52
            com.quizlet.data.repository.widget.b r1 = (com.quizlet.data.repository.widget.b) r1     // Catch: java.lang.Exception -> L52
            r5.j = r3     // Catch: java.lang.Exception -> L52
            java.lang.Object r6 = r1.r(r6, r5)     // Catch: java.lang.Exception -> L52
            if (r6 != r0) goto L4a
        L49:
            return r0
        L4a:
            java.util.List r6 = (java.util.List) r6     // Catch: java.lang.Exception -> L52
            if (r6 == 0) goto L4f
            return r6
        L4f:
            kotlin.collections.K r6 = kotlin.collections.K.a     // Catch: java.lang.Exception -> L52
            return r6
        L52:
            kotlin.collections.K r6 = kotlin.collections.K.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.notes.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
