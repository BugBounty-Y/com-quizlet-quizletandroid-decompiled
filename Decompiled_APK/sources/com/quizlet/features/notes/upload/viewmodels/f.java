package com.quizlet.features.notes.upload.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ k k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(k kVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x005a, code lost:
    
        if (r6 == r0) goto L21;
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
            com.quizlet.features.notes.upload.viewmodels.k r4 = r5.k
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L5d
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L2c
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.google.firebase.crashlytics.internal.settings.b r6 = r4.s
            r5.j = r3
            java.lang.Object r6 = r6.h(r5)
            if (r6 != r0) goto L2c
            goto L5c
        L2c:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 != 0) goto L54
            r4.getClass()
            com.quizlet.data.model.m2 r6 = com.quizlet.data.model.m2.a
            kotlinx.coroutines.flow.d0 r0 = r4.k
            com.quizlet.data.model.m2 r1 = r4.l
            if (r1 != r6) goto L46
            com.quizlet.features.notes.upload.events.a r6 = com.quizlet.features.notes.upload.events.a.a
            r0.h(r6)
            goto Ld0
        L46:
            com.quizlet.features.notes.upload.events.b r6 = new com.quizlet.features.notes.upload.events.b
            com.quizlet.features.infra.models.folders.AddMaterialFolderData r1 = r4.C()
            r6.<init>(r1)
            r0.h(r6)
            goto Ld0
        L54:
            r5.j = r2
            java.lang.Object r6 = r4.A(r5)
            if (r6 != r0) goto L5d
        L5c:
            return r0
        L5d:
            com.quizlet.data.model.w0 r6 = (com.quizlet.data.model.InterfaceC4176w0) r6
            boolean r6 = r6.a0()
            if (r6 == 0) goto L83
            r4.getClass()
            com.quizlet.data.model.m2 r6 = com.quizlet.data.model.m2.a
            kotlinx.coroutines.flow.d0 r0 = r4.k
            com.quizlet.data.model.m2 r1 = r4.l
            if (r1 != r6) goto L76
            com.quizlet.features.notes.upload.events.e r6 = com.quizlet.features.notes.upload.events.e.a
            r0.h(r6)
            goto Ld0
        L76:
            com.quizlet.features.notes.upload.events.b r6 = new com.quizlet.features.notes.upload.events.b
            com.quizlet.features.infra.models.folders.AddMaterialFolderData r1 = r4.C()
            r6.<init>(r1)
            r0.h(r6)
            goto Ld0
        L83:
            androidx.lifecycle.m0 r6 = r4.q
            r0 = 3
            r1 = 0
            java.lang.String r2 = "text"
            java.lang.Object r2 = r6.a(r2)     // Catch: java.lang.Exception -> Lc4
            java.lang.String r2 = (java.lang.String) r2     // Catch: java.lang.Exception -> Lc4
            if (r2 == 0) goto L95
            r4.M(r2)     // Catch: java.lang.Exception -> Lc4
            goto Ld0
        L95:
            java.lang.String r2 = "uris"
            java.lang.Object r6 = r6.a(r2)     // Catch: java.lang.Exception -> Lc4
            android.net.Uri[] r6 = (android.net.Uri[]) r6     // Catch: java.lang.Exception -> Lc4
            if (r6 == 0) goto Lb7
            int r2 = r6.length     // Catch: java.lang.Exception -> Lc4
            if (r2 != 0) goto Laf
            androidx.lifecycle.viewmodel.internal.a r6 = androidx.lifecycle.p0.j(r4)     // Catch: java.lang.Exception -> Lc4
            com.quizlet.features.notes.upload.viewmodels.h r2 = new com.quizlet.features.notes.upload.viewmodels.h     // Catch: java.lang.Exception -> Lc4
            r2.<init>(r1, r4, r1)     // Catch: java.lang.Exception -> Lc4
            kotlinx.coroutines.E.A(r6, r1, r1, r2, r0)     // Catch: java.lang.Exception -> Lc4
            goto Ld0
        Laf:
            java.util.List r6 = kotlin.collections.C4933y.P(r6)     // Catch: java.lang.Exception -> Lc4
            r4.L(r6)     // Catch: java.lang.Exception -> Lc4
            goto Ld0
        Lb7:
            androidx.lifecycle.viewmodel.internal.a r6 = androidx.lifecycle.p0.j(r4)     // Catch: java.lang.Exception -> Lc4
            com.quizlet.features.notes.upload.viewmodels.h r2 = new com.quizlet.features.notes.upload.viewmodels.h     // Catch: java.lang.Exception -> Lc4
            r2.<init>(r1, r4, r1)     // Catch: java.lang.Exception -> Lc4
            kotlinx.coroutines.E.A(r6, r1, r1, r2, r0)     // Catch: java.lang.Exception -> Lc4
            goto Ld0
        Lc4:
            androidx.lifecycle.viewmodel.internal.a r6 = androidx.lifecycle.p0.j(r4)
            com.quizlet.features.notes.upload.viewmodels.h r2 = new com.quizlet.features.notes.upload.viewmodels.h
            r2.<init>(r1, r4, r1)
            kotlinx.coroutines.E.A(r6, r1, r1, r2, r0)
        Ld0:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.upload.viewmodels.f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
