package com.quizlet.local.datastore.preferences;

import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.local.datastore.preferences.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4565c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ C4567d k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4565c(C4567d c4567d, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c4567d;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4565c c4565c = new C4565c(this.k, this.l, hVar);
        c4565c.j = obj;
        return c4565c;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4565c) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        androidx.datastore.preferences.core.b bVar = (androidx.datastore.preferences.core.b) this.j;
        androidx.datastore.preferences.core.f key = R6.d("PREF_EMAIL");
        bVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        bVar.f(key, this.l);
        return Unit.a;
    }
}
