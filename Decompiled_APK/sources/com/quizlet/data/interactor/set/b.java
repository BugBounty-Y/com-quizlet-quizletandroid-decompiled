package com.quizlet.data.interactor.set;

import com.quizlet.data.model.C4160q1;
import com.quizlet.data.model.C4162r1;
import io.reactivex.rxjava3.functions.h;
import kotlin.collections.A;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements h {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;

    public /* synthetic */ b(c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Throwable it2 = (Throwable) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(it2, "it");
                ((org.slf4j.b) this.b.c).c("Error retrieving school recommended sets", it2);
                return A.b(new C4162r1(K.a, null, null));
            default:
                Intrinsics.checkNotNullParameter(it2, "it");
                ((org.slf4j.b) this.b.c).c("Error retrieving behavior recommended sets", it2);
                return new C4160q1(K.a, null, null);
        }
    }
}
