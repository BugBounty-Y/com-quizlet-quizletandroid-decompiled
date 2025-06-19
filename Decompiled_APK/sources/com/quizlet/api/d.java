package com.quizlet.api;

import kotlin.jvm.internal.Intrinsics;
import retrofit2.K;

/* loaded from: classes2.dex */
public final class d implements io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public final /* synthetic */ QuizletApiClient b;

    public /* synthetic */ d(QuizletApiClient quizletApiClient, int i) {
        this.a = i;
        this.b = quizletApiClient;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                K it2 = (K) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return QuizletApiClient.C(this.b, it2);
            case 1:
                K it3 = (K) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return QuizletApiClient.C(this.b, it3);
            default:
                K it4 = (K) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                return QuizletApiClient.C(this.b, it4);
        }
    }
}
