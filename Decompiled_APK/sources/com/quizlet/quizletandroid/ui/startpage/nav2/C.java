package com.quizlet.quizletandroid.ui.startpage.nav2;

import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4721q;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Y j;
    public int k;
    public final /* synthetic */ Y l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Y y;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        Y y2 = this.l;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            y2.X.j(Boolean.TRUE);
            this.j = y2;
            this.k = 1;
            obj = y2.w.b(this);
            if (obj == aVar) {
                return aVar;
            }
            y = y2;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            y = this.j;
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        List data = Y.D(y, (List) obj, com.quizlet.quizletandroid.ui.startpage.nav2.model.P.h);
        C4721q c4721q = y2.t;
        c4721q.getClass();
        Intrinsics.checkNotNullParameter(data, "data");
        c4721q.n = data;
        y2.q1.j(new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l(data));
        y2.X.j(Boolean.FALSE);
        return Unit.a;
    }
}
