package com.quizlet.security.challenge.initializer;

import android.content.Context;
import androidx.datastore.core.C1087t;
import androidx.datastore.core.InterfaceC1076h;
import androidx.paging.J0;
import androidx.startup.b;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.data.repository.studysetwithcreatorinclass.g;
import com.quizlet.local.datastore.preferences.J;
import com.quizlet.quizletandroid.u;
import com.quizlet.security.challenge.core.e;
import com.quizlet.security.challenge.core.f;
import com.quizlet.security.challenge.core.h;
import com.quizlet.security.challenge.core.i;
import com.quizlet.security.challenge.di.a;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.W;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.internal.d;
import okhttp3.n;

@Metadata
/* loaded from: classes3.dex */
public final class SecurityChallengeDetectionInitializer implements b {
    /* JADX WARN: Type inference failed for: r0v6, types: [kotlinx.coroutines.flow.i, kotlinx.coroutines.flow.internal.a] */
    /* JADX WARN: Type inference failed for: r1v7, types: [kotlinx.coroutines.flow.i, kotlinx.coroutines.flow.internal.a] */
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Object objB = K6.b(a.class, context);
        Intrinsics.checkNotNullExpressionValue(objB, "get(...)");
        u uVar = (u) ((a) objB);
        n nVar = (n) uVar.M.get();
        com.google.mlkit.common.sdkinternal.model.a aVar = new com.google.mlkit.common.sdkinternal.model.a(29);
        J j = new J((InterfaceC1076h) uVar.L.get());
        d dVarV = uVar.V();
        E.A(dVarV, null, null, new com.quizlet.security.challenge.core.a(new g(nVar, aVar, j, dVarV), null), 3);
        i iVar = (i) uVar.b1.get();
        J0 j0 = new J0(e0.l(new J0(new C1087t((InterfaceC4992i) iVar.c.a), new com.quizlet.security.challenge.core.d(iVar, null), 5), 3000L), new e(iVar, null), 5);
        d dVar = iVar.b;
        e0.w(j0, dVar);
        e0.w(new J0(iVar.d.a, new f(iVar, null), 5), dVar);
        e0.w(new J0(new com.quizlet.analytics.marketing.appsflyer.d((W) iVar.f.a, 7), new h(iVar, null), 5), dVar);
        return Unit.a;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return K.a;
    }
}
