package com.quizlet.billing.model;

import androidx.compose.animation.d0;
import com.quizlet.billing.subscriptions.j;
import io.reactivex.rxjava3.core.p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c {
    public final long a;
    public final String b;
    public final j c;
    public final String d;
    public final p e;

    public c(long j, String productSku, j subscriptionPackage, String source, p pendingPurchaseSubscription) {
        Intrinsics.checkNotNullParameter(productSku, "productSku");
        Intrinsics.checkNotNullParameter(subscriptionPackage, "subscriptionPackage");
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(pendingPurchaseSubscription, "pendingPurchaseSubscription");
        this.a = j;
        this.b = productSku;
        this.c = subscriptionPackage;
        this.d = source;
        this.e = pendingPurchaseSubscription;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && this.c == cVar.c && Intrinsics.b(this.d, cVar.d) && Intrinsics.b(this.e, cVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.e((this.c.hashCode() + d0.e(Long.hashCode(this.a) * 31, 31, this.b)) * 31, 31, this.d);
    }

    public final String toString() {
        return "PendingPurchase(userId=" + this.a + ", productSku=" + this.b + ", subscriptionPackage=" + this.c + ", source=" + this.d + ", pendingPurchaseSubscription=" + this.e + ")";
    }
}
