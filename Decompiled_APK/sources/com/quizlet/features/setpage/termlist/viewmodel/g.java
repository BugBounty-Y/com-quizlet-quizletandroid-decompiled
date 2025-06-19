package com.quizlet.features.setpage.termlist.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.quizlet.features.setpage.termlist.data.m;
import com.quizlet.features.setpage.termlist.data.n;
import com.quizlet.features.setpage.termlist.data.o;
import com.quizlet.features.setpage.termlist.data.p;
import com.quizlet.local.datastore.preferences.C0;
import com.quizlet.local.datastore.preferences.C4567d;
import java.util.Arrays;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ j k;
    public final /* synthetic */ m l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(j jVar, m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = jVar;
        this.l = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        Object objA;
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        m mVar = this.l;
        j jVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.interactor.course.a aVar = jVar.c;
            this.j = 1;
            com.google.mlkit.vision.documentscanner.internal.c cVar = (com.google.mlkit.vision.documentscanner.internal.c) aVar.b;
            int iOrdinal = mVar.ordinal();
            C4567d c4567d = (C4567d) cVar.b;
            String str = String.format("set_page_%s_sort_option", Arrays.copyOf(new Object[]{Long.valueOf(jVar.g)}, 1));
            Intrinsics.checkNotNullExpressionValue(str, "format(...)");
            Object objD = S6.d(c4567d.a, new C0(R6.c(str), iOrdinal, null), this);
            if (objD != obj2) {
                objD = Unit.a;
            }
            if (objD != obj2) {
                objD = Unit.a;
            }
            if (objD != obj2) {
                objD = Unit.a;
            }
            if (objD == obj2) {
                return obj2;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        s0 s0Var = jVar.h;
        do {
            value = s0Var.getValue();
            objA = (p) value;
            if (objA instanceof n) {
                objA = n.a((n) objA, j.A(jVar, mVar), null, mVar, false, 22);
            } else if (!Intrinsics.b(objA, o.a)) {
                throw new NoWhenBranchMatchedException();
            }
        } while (!s0Var.k(value, objA));
        return Unit.a;
    }
}
