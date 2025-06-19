package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.local.datastore.preferences.C4566c0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.setpage.viewmodel.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4433g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4433g(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4433g(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4433g) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        P p = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            com.quizlet.data.interactor.school.b bVar = (com.quizlet.data.interactor.school.b) p.z.c;
            androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) bVar.c;
            io.reactivex.rxjava3.internal.operators.single.g gVarB = com.google.android.gms.dynamite.d.b(com.google.android.gms.dynamite.d.e(cVar.r()), cVar.q());
            io.reactivex.rxjava3.internal.operators.single.g gVarG = cVar.y().g(com.quizlet.features.setpage.upsell.b.a);
            Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
            io.reactivex.rxjava3.internal.operators.single.g gVarB2 = com.google.android.gms.dynamite.d.b(gVarB, gVarG);
            io.reactivex.rxjava3.core.p pVarP = io.reactivex.rxjava3.core.p.p(cVar.n(), cVar.o(new C4566c0(22), 0), new com.onetrust.otpublishers.headless.UI.fragment.q(bVar, 18));
            Intrinsics.checkNotNullExpressionValue(pVarP, "zip(...)");
            obj = I1.b(com.google.android.gms.dynamite.d.b(gVarB2, pVarP), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        if (((Boolean) obj).booleanValue()) {
            p.i1.j(com.quizlet.features.infra.basestudy.data.models.n.a);
        }
        return Unit.a;
    }
}
