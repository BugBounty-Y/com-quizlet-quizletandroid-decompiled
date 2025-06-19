package com.quizlet.upgrade.manager;

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
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.onetrust.otpublishers.headless.UI.TVUI.datautils.d k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = this.k;
            ((com.quizlet.infra.legacysyncengine.managers.d) ((com.lyft.android.scissors.b) dVar.a).b).c();
            io.reactivex.rxjava3.subjects.d dVar2 = ((com.quizlet.infra.legacysyncengine.managers.d) ((com.lyft.android.scissors.b) dVar.a).b).l;
            dVar2.getClass();
            J jQ = new C4887f(dVar2, 1).q(com.quizlet.billing.manager.user.a.a);
            Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
            C4986c c4986cF = K1.f(jQ);
            C0496b c0496b = new C0496b(dVar, 21);
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
