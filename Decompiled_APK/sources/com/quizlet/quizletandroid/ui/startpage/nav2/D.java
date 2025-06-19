package com.quizlet.quizletandroid.ui.startpage.nav2;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.generated.enums.I1;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4708d;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4721q;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ Y j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new D(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        List data = kotlin.collections.A.b(new C4708d(AbstractC3409x1.i(kotlin.collections.B.j(I1.LANGUAGES, I1.SCIENCE, I1.ARTS_AND_HUMANITIES, I1.MATH, I1.SOCIAL_SCIENCE))));
        Y y = this.j;
        C4721q c4721q = y.t;
        c4721q.getClass();
        Intrinsics.checkNotNullParameter(data, "data");
        c4721q.m = data;
        y.p1.j(new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l(data));
        y.W.j(Boolean.FALSE);
        return Unit.a;
    }
}
