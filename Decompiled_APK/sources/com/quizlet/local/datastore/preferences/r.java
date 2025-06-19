package com.quizlet.local.datastore.preferences;

import androidx.compose.foundation.gestures.l1;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ l1 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(l1 l1Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = l1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        r rVar = new r(this.k, hVar);
        rVar.j = obj;
        return rVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        androidx.datastore.preferences.core.b bVar = (androidx.datastore.preferences.core.b) this.j;
        androidx.datastore.preferences.core.f key = R6.a("PREF_ONBOARDING_TOOLTIP_" + this.k.b);
        Boolean bool = Boolean.TRUE;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        bVar.f(key, bool);
        return Unit.a;
    }
}
