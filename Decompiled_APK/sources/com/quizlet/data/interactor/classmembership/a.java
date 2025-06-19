package com.quizlet.data.interactor.classmembership;

import androidx.work.impl.model.v;
import com.quizlet.data.repository.classmembership.c;
import io.reactivex.rxjava3.internal.operators.completable.m;
import io.reactivex.rxjava3.internal.operators.flowable.b;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ v b;
    public final /* synthetic */ long c;

    public /* synthetic */ a(v vVar, long j, int i) {
        this.a = i;
        this.b = vVar;
        this.c = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                c cVar = (c) this.b.b;
                long j = this.c;
                m mVar = new m(new b(new com.quizlet.data.repository.classmembership.a(cVar, j, 1), 4), new com.quizlet.data.repository.classmembership.b(cVar, j, 1), null, 2);
                Intrinsics.checkNotNullExpressionValue(mVar, "onErrorReturn(...)");
                return mVar;
            default:
                return ((c) this.b.b).b(this.c);
        }
    }
}
