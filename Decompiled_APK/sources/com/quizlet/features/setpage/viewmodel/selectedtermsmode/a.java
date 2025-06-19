package com.quizlet.features.setpage.viewmodel.selectedtermsmode;

import androidx.activity.compose.p;
import androidx.compose.runtime.internal.c;
import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.J0;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ b k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, h hVar) {
        super(2, hVar);
        this.k = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            b bVar = this.k;
            Object objI = e0.i(new J0(K1.f(bVar.d.l(bVar.f, bVar.c)), new p(bVar, (h) null, 3)), new c(2, bVar, b.class, "updateSelectedState", "updateSelectedState(Ljava/util/List;)V", 4, 9), this);
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
