package com.quizlet.features.emailconfirmation.viewmodel;

import androidx.compose.material3.internal.H;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.local.datastore.preferences.C4567d;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        m mVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.lyft.android.scissors.b bVar = mVar.b;
            this.j = 1;
            C4567d c4567d = (C4567d) bVar.b;
            obj = e0.r(new H(5, c4567d.a.getData(), c4567d), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        String str = (String) obj;
        if (str != null) {
            mVar.getClass();
        } else {
            str = null;
        }
        if (str != null) {
            s0 s0Var = mVar.f;
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, com.quizlet.features.emailconfirmation.data.states.a.a((com.quizlet.features.emailconfirmation.data.states.a) value, str, null, 6)));
        } else {
            mVar.getClass();
            E.A(p0.j(mVar), null, null, new i(mVar, null), 3);
        }
        return Unit.a;
    }
}
