package com.quizlet.upgrade.viewmodel;

import androidx.compose.foundation.text.input.internal.C0496b;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.J;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.C4986c;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.lyft.android.scissors.b k;
    public final /* synthetic */ h l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.lyft.android.scissors.b bVar, h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = bVar;
        this.l = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            io.reactivex.rxjava3.subjects.d dVar = ((com.quizlet.infra.legacysyncengine.managers.d) this.k.b).l;
            dVar.getClass();
            J jQ = new C4887f(dVar, 1).q(com.quizlet.billing.manager.user.a.a);
            Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
            C4986c c4986cF = K1.f(jQ);
            C0496b c0496b = new C0496b(this.l, 22);
            this.j = 1;
            if (c4986cF.b(c0496b, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
