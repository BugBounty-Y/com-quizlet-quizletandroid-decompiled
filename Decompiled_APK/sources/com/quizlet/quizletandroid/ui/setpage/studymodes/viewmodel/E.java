package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.C1319i;
import androidx.paging.J0;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.quizlet.local.datastore.preferences.C4580p;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ G j;
    public final /* synthetic */ long k;
    public final /* synthetic */ io.reactivex.rxjava3.core.p l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(G g, long j, io.reactivex.rxjava3.core.p pVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = g;
        this.k = j;
        this.l = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new E(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        G g = this.j;
        com.quizlet.data.interactor.set.c cVar = g.a;
        long j = this.k;
        return new C4580p(new J0(K1.f(cVar.l(j, this.l)), new C1319i(g, (kotlin.coroutines.h) null, 4)), g, j, 1);
    }
}
