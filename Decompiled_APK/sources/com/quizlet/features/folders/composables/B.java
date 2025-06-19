package com.quizlet.features.folders.composables;

import android.content.Context;
import androidx.compose.material3.O3;
import com.quizlet.features.folders.data.C0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class B extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ O3 l;
    public final /* synthetic */ Context m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(O3 o3, Context context, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = o3;
        this.m = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        B b = new B(this.l, this.m, hVar);
        b.k = obj;
        return b;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((C0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0038, code lost:
    
        if (r6 == r0) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0057, code lost:
    
        if (r6 == r0) goto L20;
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
            r2 = 1
            r3 = 2
            if (r1 == 0) goto L1c
            if (r1 == r2) goto L18
            if (r1 != r3) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L5a
        L10:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L3b
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r5.k
            com.quizlet.features.folders.data.C0 r6 = (com.quizlet.features.folders.data.C0) r6
            boolean r1 = r6 instanceof com.quizlet.features.folders.data.A0
            androidx.compose.material3.O3 r4 = r5.l
            if (r1 == 0) goto L3e
            com.quizlet.features.infra.folder.menu.composable.i r1 = new com.quizlet.features.infra.folder.menu.composable.i
            com.quizlet.features.folders.data.A0 r6 = (com.quizlet.features.folders.data.A0) r6
            com.quizlet.features.infra.folder.menu.data.x r6 = r6.a
            r1.<init>(r6)
            r5.j = r2
            java.lang.Object r6 = r4.a(r1, r5)
            if (r6 != r0) goto L3b
            goto L59
        L3b:
            androidx.compose.material3.U3 r6 = (androidx.compose.material3.U3) r6
            goto L5c
        L3e:
            boolean r1 = r6 instanceof com.quizlet.features.folders.data.B0
            if (r1 == 0) goto L5f
            com.quizlet.features.folders.data.B0 r6 = (com.quizlet.features.folders.data.B0) r6
            int r6 = r6.a
            android.content.Context r1 = r5.m
            java.lang.String r6 = r1.getString(r6)
            java.lang.String r1 = "getString(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r1)
            r5.j = r3
            java.lang.Object r6 = androidx.compose.material3.O3.b(r4, r6, r5)
            if (r6 != r0) goto L5a
        L59:
            return r0
        L5a:
            androidx.compose.material3.U3 r6 = (androidx.compose.material3.U3) r6
        L5c:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L5f:
            kotlin.NoWhenBranchMatchedException r6 = new kotlin.NoWhenBranchMatchedException
            r6.<init>()
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.composables.B.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
