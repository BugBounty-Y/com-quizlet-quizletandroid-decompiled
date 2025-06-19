package com.quizlet.data.interactor.progress;

import com.braze.support.r;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3738u6;
import com.google.firebase.messaging.p;
import com.quizlet.data.model.Q;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.functions.j;
import io.reactivex.rxjava3.internal.operators.observable.J;
import io.reactivex.rxjava3.internal.operators.observable.o0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;

    public /* synthetic */ a(c cVar, long j, long j2, int i) {
        this.a = i;
        this.b = cVar;
        this.c = j;
        this.d = j2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                final com.quizlet.data.repository.progress.b bVar = (com.quizlet.data.repository.progress.b) this.b.a;
                final long j = this.c;
                final long j2 = this.d;
                J j3 = new J(((com.quizlet.data.repository.folderwithcreator.e) bVar.b).i(j, j2), new p(bVar, 14), 4);
                Intrinsics.checkNotNullExpressionValue(j3, "onErrorResumeNext(...)");
                com.jakewharton.rxbinding4.a aVar = new com.jakewharton.rxbinding4.a(new j() { // from class: com.quizlet.data.repository.progress.a
                    @Override // io.reactivex.rxjava3.functions.j
                    public final Object get() {
                        b bVar2 = bVar;
                        return AbstractC3738u6.b((com.quizlet.data.connectivity.a) bVar2.d, new r(bVar2, j, j2, 1), new com.quizlet.assembly.compose.listitems.r(17)).m();
                    }
                }, 4);
                Intrinsics.checkNotNullExpressionValue(aVar, "defer(...)");
                J j4 = new J(aVar, new com.google.firebase.crashlytics.internal.common.j(bVar, 13), 4);
                Intrinsics.checkNotNullExpressionValue(j4, "onErrorResumeNext(...)");
                o0 o0Var = new o0(i.g(j3, j4), i.p(Q.a), 0);
                Intrinsics.checkNotNullExpressionValue(o0Var, "defaultIfEmpty(...)");
                return o0Var;
            default:
                return ((com.quizlet.data.repository.folderwithcreator.e) this.b.b).i(this.c, this.d);
        }
    }
}
