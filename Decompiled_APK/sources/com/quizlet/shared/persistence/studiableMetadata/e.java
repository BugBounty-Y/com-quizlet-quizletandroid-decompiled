package com.quizlet.shared.persistence.studiableMetadata;

import com.quizlet.quizletandroid.ui.studymodes.match.fragment.t;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;

/* loaded from: classes3.dex */
public final class e implements f {
    public final u a;

    public e(com.quizlet.shared.persistence.db.persistencedatabase.c database) {
        Intrinsics.checkNotNullParameter(database, "database");
        this.a = l.b(new t(database, 9));
    }

    @Override // com.quizlet.shared.persistence.studiableMetadata.f
    public final Object b(com.quizlet.shared.models.api.keys.b bVar, com.quizlet.shared.repository.base.b bVar2) {
        return E.J(O.a, new b(this, bVar, null), bVar2);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // com.quizlet.shared.persistence.studiableMetadata.f
    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.shared.models.api.keys.b r6, assistantMode.refactored.types.StudiableMetadataContent r7, kotlin.coroutines.h r8) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r8 instanceof com.quizlet.shared.persistence.studiableMetadata.c
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.shared.persistence.studiableMetadata.c r0 = (com.quizlet.shared.persistence.studiableMetadata.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L1a
        L13:
            com.quizlet.shared.persistence.studiableMetadata.c r0 = new com.quizlet.shared.persistence.studiableMetadata.c
            kotlin.coroutines.jvm.internal.c r8 = (kotlin.coroutines.jvm.internal.c) r8
            r0.<init>(r5, r8)
        L1a:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            assistantMode.refactored.types.StudiableMetadataContent r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L49
        L2b:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlinx.coroutines.scheduling.e r8 = kotlinx.coroutines.O.a
            com.quizlet.shared.persistence.studiableMetadata.d r2 = new com.quizlet.shared.persistence.studiableMetadata.d
            r4 = 0
            r2.<init>(r5, r7, r6, r4)
            r0.j = r7
            r0.m = r3
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r2, r0)
            if (r8 != r1) goto L49
            return r1
        L49:
            java.util.List r8 = (java.util.List) r8
            assistantMode.enums.q r6 = r7.b
            assistantMode.refactored.types.StudiableMetadataContent r7 = new assistantMode.refactored.types.StudiableMetadataContent
            r7.<init>(r8, r6)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.persistence.studiableMetadata.e.a(com.quizlet.shared.models.api.keys.b, assistantMode.refactored.types.StudiableMetadataContent, kotlin.coroutines.h):java.lang.Object");
    }
}
