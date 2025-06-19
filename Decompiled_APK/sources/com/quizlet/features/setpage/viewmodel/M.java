package com.quizlet.features.setpage.viewmodel;

import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.features.setpage.screenstates.C4426f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class M implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ P a;
    public final /* synthetic */ boolean b;

    public M(P p, boolean z) {
        this.a = p;
        this.b = z;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        Object c4426f;
        com.quizlet.features.infra.basestudy.data.models.shareset.a it2 = (com.quizlet.features.infra.basestudy.data.models.shareset.a) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        P p = this.a;
        if (this.b) {
            DBStudySet dBStudySet = p.F1;
            if (dBStudySet == null) {
                Intrinsics.m("set");
                throw null;
            }
            c4426f = new com.quizlet.features.setpage.screenstates.g(dBStudySet, it2);
        } else {
            DBStudySet dBStudySet2 = p.F1;
            if (dBStudySet2 == null) {
                Intrinsics.m("set");
                throw null;
            }
            c4426f = new C4426f(dBStudySet2, it2);
        }
        io.reactivex.rxjava3.internal.operators.flowable.b bVarF = io.reactivex.rxjava3.core.p.f(c4426f);
        Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
        io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(bVarF, io.reactivex.rxjava3.kotlin.c.b, new C4429c(p, 0));
        Intrinsics.checkNotNullParameter(eVarB, "<this>");
        p.A(eVarB);
    }
}
