package com.perimeterx.mobile_sdk.local_data;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ String k;
    public final /* synthetic */ int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(String str, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        t tVar = new t(this.k, this.l, hVar);
        tVar.j = obj;
        return tVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        androidx.datastore.preferences.core.b bVar = (androidx.datastore.preferences.core.b) this.j;
        androidx.datastore.preferences.core.f key = R6.c(this.k);
        Integer num = new Integer(this.l);
        bVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        bVar.f(key, num);
        return Unit.a;
    }
}
