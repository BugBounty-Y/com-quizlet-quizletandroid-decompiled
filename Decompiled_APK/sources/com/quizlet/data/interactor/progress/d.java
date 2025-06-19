package com.quizlet.data.interactor.progress;

import io.reactivex.rxjava3.subjects.r;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function1 {
    public final /* synthetic */ c a;
    public final /* synthetic */ long b;
    public final /* synthetic */ long c;

    public /* synthetic */ d(c cVar, long j, long j2) {
        this.a = cVar;
        this.b = j;
        this.c = j2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        r destroyToken = (r) obj;
        Intrinsics.checkNotNullParameter(destroyToken, "destroyToken");
        return this.a.f(this.b, this.c, destroyToken);
    }
}
