package com.google.firebase.sessions.settings;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Object k;
    public final /* synthetic */ androidx.datastore.preferences.core.f l;
    public final /* synthetic */ n m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(Object obj, androidx.datastore.preferences.core.f fVar, n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = obj;
        this.l = fVar;
        this.m = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        m mVar = new m(this.k, this.l, this.m, hVar);
        mVar.j = obj;
        return mVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        androidx.datastore.preferences.core.b bVar = (androidx.datastore.preferences.core.b) this.j;
        Object obj2 = this.k;
        androidx.datastore.preferences.core.f fVar = this.l;
        if (obj2 != null) {
            bVar.e(fVar, obj2);
        } else {
            bVar.d(fVar);
        }
        n.a(this.m, bVar);
        return Unit.a;
    }
}
