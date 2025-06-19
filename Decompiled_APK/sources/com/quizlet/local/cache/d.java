package com.quizlet.local.cache;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.squareup.moshi.l;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ String k;
    public final /* synthetic */ androidx.work.impl.model.e l;
    public final /* synthetic */ List m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(String str, androidx.work.impl.model.e eVar, List list, h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = eVar;
        this.m = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        d dVar = new d(this.k, this.l, this.m, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((androidx.datastore.preferences.core.b) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        androidx.datastore.preferences.core.b bVar = (androidx.datastore.preferences.core.b) this.j;
        androidx.datastore.preferences.core.f key = R6.d(this.k);
        androidx.work.impl.model.e eVar = this.l;
        String strF = ((l) eVar.b).f(this.m);
        bVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        bVar.f(key, strF);
        return Unit.a;
    }
}
