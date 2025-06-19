package com.quizlet.billing.subscriptions;

import io.reactivex.rxjava3.internal.operators.observable.C4888g;
import io.reactivex.rxjava3.internal.operators.observable.J;
import io.reactivex.rxjava3.subjects.r;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i {
    public final com.quizlet.billing.manager.f a;
    public final com.google.android.material.floatingactionbutton.c b;
    public final com.quizlet.billing.manager.sku.a c;

    public i(com.quizlet.billing.manager.f billingManager, com.google.android.material.floatingactionbutton.c skuManager, com.quizlet.billing.manager.sku.a skuResolver) {
        Intrinsics.checkNotNullParameter(billingManager, "billingManager");
        Intrinsics.checkNotNullParameter(skuManager, "skuManager");
        Intrinsics.checkNotNullParameter(skuResolver, "skuResolver");
        this.a = billingManager;
        this.b = skuManager;
        this.c = skuResolver;
    }

    public final io.reactivex.rxjava3.internal.operators.maybe.h a(j subscriptionPackage) {
        Intrinsics.checkNotNullParameter(subscriptionPackage, "subscriptionPackage");
        r rVar = this.a.g;
        com.quizlet.data.repository.explanations.myexplanations.a aVar = new com.quizlet.data.repository.explanations.myexplanations.a(this, false, subscriptionPackage, 14);
        rVar.getClass();
        io.reactivex.rxjava3.internal.operators.maybe.h hVar = new io.reactivex.rxjava3.internal.operators.maybe.h(3, rVar, aVar);
        Intrinsics.checkNotNullExpressionValue(hVar, "flatMapMaybe(...)");
        return hVar;
    }

    public final C4888g b(com.quizlet.billing.model.b user) {
        Intrinsics.checkNotNullParameter(user, "user");
        J j = new J(io.reactivex.rxjava3.core.i.n(Arrays.copyOf(com.quizlet.billing.manager.f.l, 20)), new com.quizlet.data.repository.qclass.c(14, this, user), 1);
        Intrinsics.checkNotNullExpressionValue(j, "flatMapSingle(...)");
        Intrinsics.checkNotNullParameter(j, "<this>");
        C4888g c4888g = new C4888g(j);
        Intrinsics.checkNotNullExpressionValue(c4888g, "any(...)");
        return c4888g;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x007e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final io.reactivex.rxjava3.internal.operators.completable.m c(java.lang.String r10, com.quizlet.billing.model.b r11) {
        /*
            Method dump skipped, instructions count: 271
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.billing.subscriptions.i.c(java.lang.String, com.quizlet.billing.model.b):io.reactivex.rxjava3.internal.operators.completable.m");
    }
}
