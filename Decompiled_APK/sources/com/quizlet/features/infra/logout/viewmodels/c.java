package com.quizlet.features.infra.logout.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.quizletandroid.managers.u;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ d k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(d dVar, boolean z, h hVar) {
        super(2, hVar);
        this.k = dVar;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        d dVar = this.k;
        if (i == 0) {
            Z.e(obj);
            u uVar = dVar.a;
            this.j = 1;
            obj = uVar.b(this.l, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        EnumC4167t0 enumC4167t0 = (EnumC4167t0) obj;
        int iOrdinal = enumC4167t0.ordinal();
        if (iOrdinal == 0) {
            dVar.v(enumC4167t0);
        } else {
            if (iOrdinal != 1 && iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            dVar.f.h(enumC4167t0);
        }
        return Unit.a;
    }
}
