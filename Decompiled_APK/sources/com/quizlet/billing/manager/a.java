package com.quizlet.billing.manager;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.android.billingclient.api.C1472a;
import com.android.billingclient.api.C1473b;
import com.android.billingclient.api.Purchase;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;
    public final /* synthetic */ r c;

    public /* synthetic */ a(f fVar, r rVar, int i) {
        this.a = i;
        this.b = fVar;
        this.c = rVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x00a3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void a(com.android.billingclient.api.e r6, java.util.ArrayList r7) {
        /*
            Method dump skipped, instructions count: 238
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.billing.manager.a.a(com.android.billingclient.api.e, java.util.ArrayList):void");
    }

    public void b(com.android.billingclient.api.e billingResult, List purchases) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(billingResult, "billingResult");
                Intrinsics.checkNotNullParameter(purchases, "purchases");
                int i = billingResult.a;
                r rVar = this.c;
                if (i != 0) {
                    timber.log.c.a.e(new BillingLibraryException(billingResult.a, "Error occurred retrieving existing purchases"));
                    rVar.onSuccess(Unit.a);
                    return;
                }
                f fVar = this.b;
                com.quizlet.billing.model.a aVar = fVar.d;
                Purchase[] purchaseArr = (Purchase[]) purchases.toArray(new Purchase[0]);
                aVar.a((Purchase[]) Arrays.copyOf(purchaseArr, purchaseArr.length));
                ArrayList arrayList = new ArrayList();
                for (Object obj : purchases) {
                    if (!((Purchase) obj).c.optBoolean("acknowledged", true)) {
                        arrayList.add(obj);
                    }
                }
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    Purchase purchase = (Purchase) it2.next();
                    String strB = purchase.b();
                    if (strB == null) {
                        throw new IllegalArgumentException("Purchase token must be set");
                    }
                    C1472a c1472a = new C1472a();
                    c1472a.b = strB;
                    Intrinsics.checkNotNullExpressionValue(c1472a, "with(...)");
                    timber.log.c.a.g(AbstractC0147y.d("Purchase acknowledgement on android side, purchase: ", purchase.b()), new Object[0]);
                    C1473b c1473b = fVar.e;
                    if (c1473b == null) {
                        Intrinsics.m("billingClient");
                        throw null;
                    }
                    c1473b.a(c1472a, new com.google.android.material.search.a(purchase, 17));
                }
                rVar.onSuccess(Unit.a);
                return;
            default:
                Intrinsics.checkNotNullParameter(billingResult, "billingResult");
                Intrinsics.checkNotNullParameter(purchases, "purchases");
                int i2 = billingResult.a;
                r rVar2 = this.c;
                if (i2 != 0 || purchases.isEmpty()) {
                    rVar2.onError(new BillingLibraryException(billingResult.a, "Failed to retrieve latest purchases"));
                    return;
                }
                com.quizlet.billing.model.a aVar2 = this.b.d;
                aVar2.getClass();
                Intrinsics.checkNotNullParameter(purchases, "purchases");
                aVar2.c.clear();
                Purchase[] purchaseArr2 = (Purchase[]) purchases.toArray(new Purchase[0]);
                aVar2.a((Purchase[]) Arrays.copyOf(purchaseArr2, purchaseArr2.length));
                rVar2.onSuccess(CollectionsKt.L(purchases));
                return;
        }
    }
}
