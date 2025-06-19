package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ G j;
    public final /* synthetic */ boolean k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(G g, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = g;
        this.k = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new w(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((w) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        com.quizlet.data.repository.progress.b bVar;
        StudiableTaskProgress studiableTaskProgressB;
        s0 s0Var;
        Object value;
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        List list = G.D1;
        G g = this.j;
        if (!g.P() && ((studiableTaskProgressB = (bVar = g.f).b()) == null || (i4 = studiableTaskProgressB.a) == 0 || (i5 = studiableTaskProgressB.b) == 0 || i4 != i5)) {
            k kVar = new k(g, 1);
            do {
                s0Var = g.J;
                value = s0Var.getValue();
                StudiableTaskProgress studiableTaskProgressB2 = bVar.b();
                if (studiableTaskProgressB2 != null) {
                    i = studiableTaskProgressB2.a;
                    i2 = 0;
                } else {
                    i = 0;
                    i2 = 0;
                }
                i3 = g.s1;
                StudiableTaskProgress studiableTaskProgressB3 = bVar.b();
                if (studiableTaskProgressB3 != null) {
                    i2 = studiableTaskProgressB3.b;
                }
            } while (!s0Var.k(value, new com.quizlet.learn.ui.toolbar.g(new com.quizlet.learn.ui.toolbar.c(new com.quizlet.learn.ui.progress.g(i, i3, i2, this.k ? com.quizlet.learn.ui.progress.i.d : com.quizlet.learn.ui.progress.i.e, new Long(200L), kVar)), null)));
        }
        return Unit.a;
    }
}
