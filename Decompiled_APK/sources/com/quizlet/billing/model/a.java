package com.quizlet.billing.model;

import com.android.billingclient.api.Purchase;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final LinkedHashMap a = new LinkedHashMap();
    public final LinkedHashMap b = new LinkedHashMap();
    public final LinkedHashMap c = new LinkedHashMap();

    public final void a(Purchase... purchases) {
        Intrinsics.checkNotNullParameter(purchases, "purchases");
        for (Purchase purchase : purchases) {
            ArrayList arrayListA = purchase.a();
            Intrinsics.checkNotNullExpressionValue(arrayListA, "getProducts(...)");
            Iterator it2 = arrayListA.iterator();
            while (it2.hasNext()) {
                this.c.put((String) it2.next(), purchase);
            }
        }
    }

    public final Purchase b() {
        Object objPrevious;
        List listN0 = CollectionsKt.n0(this.c.values(), new com.google.zxing.aztec.encoder.c(6));
        ListIterator listIterator = listN0.listIterator(listN0.size());
        while (true) {
            if (!listIterator.hasPrevious()) {
                objPrevious = null;
                break;
            }
            objPrevious = listIterator.previous();
            if (((Purchase) objPrevious).c.optBoolean("autoRenewing")) {
                break;
            }
        }
        Purchase purchase = (Purchase) objPrevious;
        return purchase == null ? (Purchase) CollectionsKt.V(listN0) : purchase;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("purchases: " + this.c + " |  available subs: " + this.a);
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}
