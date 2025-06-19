package com.quizlet.billing.manager;

import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class BillingLibraryException extends Exception {
    public final int a;
    public final String b;

    public BillingLibraryException(int i, String str) {
        this.a = i;
        this.b = str;
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return "Billing operation failed. Error code = " + this.a + " (see BillingClient.BillingResponse for details). " + this.b;
    }
}
