package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.folders.data.Q0;
import com.quizlet.features.folders.data.U;
import com.quizlet.features.folders.data.W;
import com.quizlet.features.folders.data.Y0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class M extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public N j;
    public int k;
    public final /* synthetic */ N l;
    public final /* synthetic */ String m;
    public final /* synthetic */ long n;
    public final /* synthetic */ long o;
    public final /* synthetic */ boolean p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(N n, String str, long j, long j2, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = n;
        this.m = str;
        this.n = j;
        this.o = j2;
        this.p = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new M(this.l, this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((M) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objN;
        N n;
        Object value;
        U u;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        N n2 = this.l;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.interactor.folderwithcreator.m mVar = n2.d;
            this.j = n2;
            this.k = 1;
            objN = mVar.n(n2.r, this.m, this.n, this.o, this.p, this);
            if (objN == aVar) {
                return aVar;
            }
            n = n2;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            n = this.j;
            Z.e(obj);
            objN = ((kotlin.r) obj).a;
        }
        kotlin.p pVar = kotlin.r.b;
        if (!(objN instanceof kotlin.q)) {
            Y0 y0 = (Y0) objN;
            s0 s0Var = n2.u;
            do {
                value = s0Var.getValue();
                W w = (W) value;
                Intrinsics.e(w, "null cannot be cast to non-null type com.quizlet.features.folders.data.FolderHeaderState.Content");
                u = (U) w;
            } while (!s0Var.k(value, U.a(u, Q0.a(u.a, y0.a, y0.b, false, null, 0L, 1048572), false, 2)));
        }
        n.N(objN, true);
        return Unit.a;
    }
}
