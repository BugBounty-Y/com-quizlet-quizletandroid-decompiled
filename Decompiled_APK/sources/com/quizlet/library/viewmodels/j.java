package com.quizlet.library.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.data.model.S0;
import com.quizlet.data.model.T0;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ l k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object value;
        ArrayList arrayList;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        l lVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.interactor.course.e eVar = lVar.b;
            this.j = 1;
            obj = eVar.d(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        List<T0> list = (List) obj;
        if (list.isEmpty()) {
            lVar.getClass();
            E.A(p0.j(lVar), null, null, new k(lVar, null), 3);
        } else {
            s0 s0Var = lVar.d;
            do {
                value = s0Var.getValue();
                arrayList = new ArrayList();
                for (T0 t0 : list) {
                    arrayList.add(new u(t0.a));
                    for (S0 s0 : t0.b) {
                        Intrinsics.checkNotNullParameter(s0, "<this>");
                        arrayList.add(new t(s0, new com.quizlet.ui.models.content.listitem.g(s0.a, s0.b)));
                    }
                }
            } while (!s0Var.k(value, new f(AbstractC3409x1.i(arrayList))));
        }
        return Unit.a;
    }
}
