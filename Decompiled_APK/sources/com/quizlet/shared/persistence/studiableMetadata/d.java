package com.quizlet.shared.persistence.studiableMetadata;

import assistantMode.refactored.types.StudiableMetadataContent;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public final /* synthetic */ e j;
    public final /* synthetic */ StudiableMetadataContent k;
    public final /* synthetic */ com.quizlet.shared.models.api.keys.b l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e eVar, StudiableMetadataContent studiableMetadataContent, com.quizlet.shared.models.api.keys.b bVar, h hVar) {
        super(2, hVar);
        this.j = eVar;
        this.k = studiableMetadataContent;
        this.l = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x00a5  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) throws java.lang.Throwable {
        /*
            r11 = this;
            r1 = 0
            r0 = 1
            java.lang.String r2 = "mapper"
            kotlin.coroutines.intrinsics.a r3 = kotlin.coroutines.intrinsics.a.a
            androidx.glance.appwidget.protobuf.Z.e(r12)
            com.quizlet.shared.persistence.studiableMetadata.e r12 = r11.j
            kotlin.u r12 = r12.a
            java.lang.Object r12 = r12.getValue()
            r4 = r12
            com.quizlet.shared.persistence.db.g r4 = (com.quizlet.shared.persistence.db.g) r4
            assistantMode.refactored.types.StudiableMetadataContent r12 = r11.k
            java.util.List r5 = r12.a
            com.quizlet.shared.models.api.keys.b r12 = r11.l
            long r6 = r12.a
            assistantMode.refactored.enums.j r3 = assistantMode.refactored.enums.j.b
            r4.getClass()
            java.lang.String r8 = "studiableContainerType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r8)
            assistantMode.enums.s r12 = r12.b
            java.lang.String r9 = "studiableMetadataType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r9)
            com.quizlet.shared.persistence.db.a r10 = com.quizlet.shared.persistence.db.a.d
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r8)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r9)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r2)
            com.quizlet.shared.persistence.db.e r3 = new com.quizlet.shared.persistence.db.e
            com.quizlet.shared.persistence.db.f r9 = new com.quizlet.shared.persistence.db.f
            r9.<init>(r4, r0)
            r8 = r12
            r3.<init>(r4, r5, r6, r8, r9)
            androidx.credentials.playservices.controllers.BeginSignIn.c r12 = new androidx.credentials.playservices.controllers.BeginSignIn.c
            r4 = 8
            r12.<init>(r3, r4)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r2)
            androidx.activity.compose.g r2 = new androidx.activity.compose.g
            com.quizlet.shared.persistence.db.g r4 = r3.g
            r5 = 27
            r2.<init>(r4, r12, r3, r5)
            java.lang.String r12 = "bodyWithReturn"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r12)
            java.lang.Object r12 = r4.b
            app.cash.sqldelight.driver.android.i r12 = (app.cash.sqldelight.driver.android.i) r12
            java.lang.ThreadLocal r3 = r12.b
            java.lang.Object r5 = r3.get()
            app.cash.sqldelight.driver.android.e r5 = (app.cash.sqldelight.driver.android.e) r5
            app.cash.sqldelight.driver.android.e r6 = new app.cash.sqldelight.driver.android.e
            r6.<init>(r12, r5)
            r3.set(r6)
            if (r5 != 0) goto L78
            androidx.sqlite.db.framework.b r12 = r12.i()
            r12.d()
        L78:
            app.cash.sqldelight.driver.android.e r12 = r6.h
            app.cash.sqldelight.a r3 = new app.cash.sqldelight.a     // Catch: java.lang.Throwable -> L93
            java.lang.String r5 = "transaction"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r5)     // Catch: java.lang.Throwable -> L93
            r3.<init>()     // Catch: java.lang.Throwable -> L93
            java.lang.Object r2 = r2.invoke(r3)     // Catch: java.lang.Throwable -> L93
            r6.f = r0     // Catch: java.lang.Throwable -> L91
            r6.a()
            r4.K(r6, r12, r1, r2)
            goto L9b
        L91:
            r0 = move-exception
            goto L95
        L93:
            r0 = move-exception
            r2 = r1
        L95:
            r6.a()
            r4.K(r6, r12, r0, r2)
        L9b:
            app.cash.sqldelight.db.d r2 = (app.cash.sqldelight.db.d) r2
            app.cash.sqldelight.db.c r2 = (app.cash.sqldelight.db.c) r2
            java.lang.Object r12 = r2.b
            com.quizlet.shared.persistence.db.i r12 = (com.quizlet.shared.persistence.db.i) r12
            if (r12 == 0) goto La7
            java.util.List r1 = r12.a
        La7:
            kotlin.jvm.internal.Intrinsics.d(r1)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.persistence.studiableMetadata.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
