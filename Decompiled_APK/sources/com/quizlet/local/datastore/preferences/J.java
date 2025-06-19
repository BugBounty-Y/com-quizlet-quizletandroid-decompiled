package com.quizlet.local.datastore.preferences;

import androidx.compose.material.C0574q;
import androidx.datastore.core.C1085q;
import androidx.datastore.core.InterfaceC1076h;
import androidx.paging.C1319i;
import androidx.paging.J0;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class J {
    public final InterfaceC1076h a;

    public J(InterfaceC1076h dataStore) {
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.a = dataStore;
    }

    public final Object a(String str, kotlin.coroutines.jvm.internal.c cVar) {
        kotlin.coroutines.h hVar = null;
        return kotlinx.coroutines.flow.e0.r(new androidx.compose.material3.internal.H(7, new J0(new J0(new J0(this.a.getData(), new C1319i(this, hVar, 3)), new C0574q(this, hVar, 6)), new C1085q(3, 2, null)), R6.d(str)), cVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0068 A[ORIG_RETURN, RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof com.quizlet.local.datastore.preferences.G
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.local.datastore.preferences.G r0 = (com.quizlet.local.datastore.preferences.G) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.G r0 = new com.quizlet.local.datastore.preferences.G
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            java.lang.Object r0 = r0.j
            java.lang.String r0 = (java.lang.String) r0
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L64
        L2e:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L36:
            java.lang.Object r2 = r0.j
            com.quizlet.local.datastore.preferences.J r2 = (com.quizlet.local.datastore.preferences.J) r2
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r6
            r0.m = r4
            java.lang.String r7 = "QLTJ_KEY"
            java.lang.Object r7 = r6.a(r7, r0)
            if (r7 != r1) goto L4e
            goto L60
        L4e:
            r2 = r6
        L4f:
            java.lang.String r7 = (java.lang.String) r7
            if (r7 != 0) goto L54
            goto L68
        L54:
            r0.j = r7
            r0.m = r3
            java.lang.String r3 = "QLTJ_DOMAIN_KEY"
            java.lang.Object r0 = r2.a(r3, r0)
            if (r0 != r1) goto L61
        L60:
            return r1
        L61:
            r5 = r0
            r0 = r7
            r7 = r5
        L64:
            java.lang.String r7 = (java.lang.String) r7
            if (r7 != 0) goto L6a
        L68:
            r7 = 0
            return r7
        L6a:
            com.quizlet.local.datastore.preferences.B r1 = new com.quizlet.local.datastore.preferences.B
            r1.<init>(r0, r7)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.local.datastore.preferences.J.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object c(String str, String str2, kotlin.coroutines.jvm.internal.c cVar) {
        Object objD = S6.d(this.a, new H(R6.d(str), str2, null), cVar);
        return objD == kotlin.coroutines.intrinsics.a.a ? objD : Unit.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x005e, code lost:
    
        if (r2.c("QLTJ_DOMAIN_KEY", r6, r0) == r1) goto L22;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(com.quizlet.local.datastore.preferences.B r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.local.datastore.preferences.I
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.local.datastore.preferences.I r0 = (com.quizlet.local.datastore.preferences.I) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.I r0 = new com.quizlet.local.datastore.preferences.I
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L61
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            com.quizlet.local.datastore.preferences.B r6 = r0.k
            com.quizlet.local.datastore.preferences.J r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.String r7 = r6.a
            r0.j = r5
            r0.k = r6
            r0.n = r4
            java.lang.String r2 = "QLTJ_KEY"
            java.lang.Object r7 = r5.c(r2, r7, r0)
            if (r7 != r1) goto L4e
            goto L60
        L4e:
            r2 = r5
        L4f:
            java.lang.String r6 = r6.b
            r7 = 0
            r0.j = r7
            r0.k = r7
            r0.n = r3
            java.lang.String r7 = "QLTJ_DOMAIN_KEY"
            java.lang.Object r6 = r2.c(r7, r6, r0)
            if (r6 != r1) goto L61
        L60:
            return r1
        L61:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.local.datastore.preferences.J.d(com.quizlet.local.datastore.preferences.B, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
