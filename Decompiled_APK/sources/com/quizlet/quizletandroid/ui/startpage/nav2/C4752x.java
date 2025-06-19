package com.quizlet.quizletandroid.ui.startpage.nav2;

import com.google.android.gms.internal.ads.C3;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4705a;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4721q;
import java.time.LocalDate;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.x, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4752x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Y k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4752x(Y y, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = y;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4752x(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4752x) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        androidx.camera.core.impl.utils.e eVarS;
        List data;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        Y y = this.k;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                y.K.j(Boolean.TRUE);
                androidx.work.impl.model.e eVar = y.l;
                boolean z = this.l;
                this.j = 1;
                com.google.firebase.messaging.p pVar = (com.google.firebase.messaging.p) ((C3) eVar.b).f;
                LocalDate localDateNow = LocalDate.now();
                Intrinsics.checkNotNullExpressionValue(localDateNow, "now(...)");
                obj = kotlinx.coroutines.E.m(new com.quizlet.data.interactor.achievements.m(pVar, localDateNow, null, z), this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
            y.s.getClass();
            eVarS = com.google.mlkit.common.sdkinternal.model.a.s((com.quizlet.data.interactor.achievements.g) obj);
        } catch (Exception e) {
            timber.log.c.a.h(e);
            eVarS = null;
        }
        if (eVarS != null) {
            List listB = kotlin.collections.A.b(new C4705a(eVarS));
            y.getClass();
            data = kotlin.jvm.internal.O.b(CollectionsKt.y0(Y.F(Y.G(listB), com.quizlet.quizletandroid.ui.startpage.nav2.model.P.f, null)));
            C4721q c4721q = y.t;
            c4721q.getClass();
            Intrinsics.checkNotNullParameter(data, "data");
            c4721q.j = data;
        } else {
            data = kotlin.collections.K.a;
        }
        y.n1.j(new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.i(data));
        y.K.j(Boolean.FALSE);
        return Unit.a;
    }
}
