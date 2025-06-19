package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.folders.data.C4314w0;
import com.quizlet.features.folders.data.C4316x0;
import com.quizlet.features.folders.data.z0;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ N k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new u(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objT;
        Object value;
        Object value2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        N n = this.k;
        if (i == 0) {
            Z.e(obj);
            io.ktor.client.plugins.api.d dVar = n.i;
            this.j = 1;
            objT = dVar.t(n.r, this);
            if (objT == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objT = ((kotlin.r) obj).a;
        }
        kotlin.p pVar = kotlin.r.b;
        if (!(objT instanceof kotlin.q)) {
            Pair pair = (Pair) objT;
            z0 z0Var = (z0) pair.a;
            kotlinx.collections.immutable.b bVar = (kotlinx.collections.immutable.b) pair.b;
            s0 s0Var = n.y;
            do {
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, new C4314w0(z0Var, bVar)));
        }
        if (kotlin.r.a(objT) != null) {
            s0 s0Var2 = n.y;
            do {
                value = s0Var2.getValue();
            } while (!s0Var2.k(value, C4316x0.a));
        }
        return Unit.a;
    }
}
