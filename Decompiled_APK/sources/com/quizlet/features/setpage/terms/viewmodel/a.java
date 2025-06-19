package com.quizlet.features.setpage.terms.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.J0;
import com.braze.C1510p;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.quizlet.data.interactor.folderwithcreator.k;
import io.reactivex.rxjava3.subjects.r;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, boolean z, h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        io.reactivex.rxjava3.core.i iVarL;
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            c cVar = this.k;
            r stopToken = cVar.c;
            boolean z = this.l;
            long j = cVar.i;
            com.quizlet.data.interactor.set.c cVar2 = cVar.d;
            if (z) {
                cVar2.getClass();
                Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                iVarL = ((androidx.work.impl.model.c) cVar2.b).b(stopToken, new C1510p(cVar2, j, 17));
            } else {
                iVarL = cVar2.l(j, stopToken);
            }
            Object objI = e0.i(new J0(K1.f(iVarL), new k(cVar, (h) null)), new androidx.compose.runtime.internal.c(2, cVar, c.class, "onTermsUpdated", "onTermsUpdated(Ljava/util/List;)V", 4, 7), this);
            if (objI != obj2) {
                objI = Unit.a;
            }
            if (objI == obj2) {
                return obj2;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
