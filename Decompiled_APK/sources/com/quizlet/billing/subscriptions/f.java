package com.quizlet.billing.subscriptions;

import com.android.billingclient.api.Purchase;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3722s6;
import com.quizlet.billing.manager.BillingLibraryException;
import io.reactivex.rxjava3.core.p;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;

    public /* synthetic */ f(h hVar, int i) {
        this.a = i;
        this.b = hVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                Purchase purchase = (Purchase) obj;
                h hVar = this.b;
                com.quizlet.billing.model.b bVarE = hVar.b.e();
                com.quizlet.billing.register.a aVar = hVar.d;
                long j = bVarE.a;
                return !aVar.d(j) ? io.reactivex.rxjava3.internal.operators.maybe.f.a : new io.reactivex.rxjava3.internal.operators.maybe.e(new io.reactivex.rxjava3.internal.operators.flowable.b(new e(j, purchase, hVar, AbstractC3722s6.d(purchase), "sync"), 4), 3);
            case 1:
                Purchase purchase2 = (Purchase) obj;
                h hVar2 = this.b;
                return new io.reactivex.rxjava3.internal.operators.flowable.b(new e(hVar2.b.e().a, purchase2, hVar2, AbstractC3722s6.d(purchase2), "sync"), 4);
            case 2:
                Integer num = (Integer) obj;
                return num.intValue() != 0 ? p.d(new BillingLibraryException(num.intValue(), null)) : this.b.i.g;
            default:
                String str = (String) obj;
                h hVar3 = this.b;
                return new io.reactivex.rxjava3.internal.operators.maybe.j(new io.reactivex.rxjava3.internal.operators.maybe.h(3, hVar3.c.c(str, hVar3.b.e()), new com.google.firebase.tracing.a(str, 5, hVar3)), new f(hVar3, 0), 0);
        }
    }
}
