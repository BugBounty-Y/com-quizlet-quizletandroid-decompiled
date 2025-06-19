package com.quizlet.local.datastore.preferences;

import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.local.datastore.preferences.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4561a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ C4567d k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4561a(C4567d c4567d, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c4567d;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4561a c4561a = new C4561a(this.k, hVar);
        c4561a.j = obj;
        return c4561a;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4561a) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        ((androidx.datastore.preferences.core.b) this.j).d(R6.d("PREF_EMAIL"));
        return Unit.a;
    }
}
