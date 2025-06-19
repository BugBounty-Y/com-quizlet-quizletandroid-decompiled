package com.quizlet.library.viewmodels;

import androidx.compose.ui.node.B;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.X5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.data.model.B0;
import com.quizlet.data.model.C0;
import com.quizlet.data.model.D0;
import com.quizlet.data.model.E0;
import com.quizlet.data.model.Y;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ s k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(s sVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        ArrayList arrayList;
        Object bVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        s sVar = this.k;
        if (i == 0) {
            Z.e(obj);
            io.reactivex.rxjava3.internal.operators.single.g gVarG = sVar.d.g(null, Y.a(), sVar.c);
            this.j = 1;
            obj = I1.b(gVarG, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        Intrinsics.checkNotNullExpressionValue(obj, "await(...)");
        List<B0> list = (List) obj;
        if (list.isEmpty()) {
            sVar.getClass();
            E.A(p0.j(sVar), null, null, new r(sVar, null), 3);
        } else {
            s0 s0Var = sVar.e;
            do {
                value = s0Var.getValue();
                arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                for (B0 b0 : list) {
                    if (b0 instanceof D0) {
                        D0 d0 = (D0) b0;
                        Intrinsics.checkNotNullParameter(d0, "<this>");
                        bVar = new w(new com.quizlet.ui.models.content.listitem.p(d0.b, d0.c, d0.e, d0.i));
                    } else if (b0 instanceof E0) {
                        bVar = new v(X5.g((E0) b0));
                    } else {
                        if (!(b0 instanceof C0)) {
                            throw new IllegalArgumentException(B.d(b0.getClass(), "Unknown type: "));
                        }
                        C0 c0 = (C0) b0;
                        Intrinsics.checkNotNullParameter(c0, "<this>");
                        bVar = new b(new com.quizlet.ui.models.content.listitem.c(c0.d, c0.g));
                    }
                    arrayList.add(bVar);
                }
            } while (!s0Var.k(value, new m(AbstractC3409x1.i(arrayList))));
        }
        return Unit.a;
    }
}
