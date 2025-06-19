package com.quizlet.billing.manager.sku;

import com.lyft.android.scissors.b;
import com.quizlet.billing.subscriptions.j;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final b a;

    public a(b billingUserManager) {
        Intrinsics.checkNotNullParameter(billingUserManager, "billingUserManager");
        this.a = billingUserManager;
    }

    public final String a(j subscriptionPackage) {
        Intrinsics.checkNotNullParameter(subscriptionPackage, "subscriptionPackage");
        if (this.a.e().e) {
            int iOrdinal = subscriptionPackage.ordinal();
            if (iOrdinal == 0) {
                throw new IllegalArgumentException("Should not request sku when tier is " + subscriptionPackage);
            }
            if (iOrdinal == 1) {
                return "com.quizlet.quizletandroid.go.autorenewing.1year.trial7day.international.prices.2021";
            }
            if (iOrdinal == 2) {
                return "com.quizlet.quizletandroid.plus.autorenewing.1year.trial7day.international.prices.2021";
            }
            if (iOrdinal == 3) {
                return "com.quizlet.quizletandroid.teacher.autorenewing.1year.trial30day.bts2021";
            }
            if (iOrdinal == 4) {
                return "com.quizlet.quizletandroid.plus.autorenewing.1month";
            }
            throw new NoWhenBranchMatchedException();
        }
        int iOrdinal2 = subscriptionPackage.ordinal();
        if (iOrdinal2 == 0) {
            throw new IllegalArgumentException("Should not request sku when tier is " + subscriptionPackage);
        }
        if (iOrdinal2 == 1) {
            return "com.quizlet.quizletandroid.go.autorenewing.1year.international.prices.2021";
        }
        if (iOrdinal2 == 2) {
            return "com.quizlet.quizletandroid.plus.autorenewing.1year.international.prices.2021";
        }
        if (iOrdinal2 == 3) {
            return "com.quizlet.quizletandroid.teacher.autorenewing.1year.bts2021";
        }
        if (iOrdinal2 == 4) {
            return "com.quizlet.quizletandroid.plus.autorenewing.1month";
        }
        throw new NoWhenBranchMatchedException();
    }
}
