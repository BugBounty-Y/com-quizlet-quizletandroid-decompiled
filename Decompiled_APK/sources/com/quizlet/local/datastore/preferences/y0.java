package com.quizlet.local.datastore.preferences;

import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.local.datastore.models.metering.i k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y0(com.quizlet.local.datastore.models.metering.i iVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        y0 y0Var = new y0(this.k, this.l, hVar);
        y0Var.j = obj;
        return y0Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((y0) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        androidx.datastore.preferences.core.b bVar = (androidx.datastore.preferences.core.b) this.j;
        androidx.datastore.preferences.core.f key = R6.a("PREF_SOUND");
        Boolean boolValueOf = Boolean.valueOf(this.l);
        bVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        bVar.f(key, boolValueOf);
        return Unit.a;
    }
}
