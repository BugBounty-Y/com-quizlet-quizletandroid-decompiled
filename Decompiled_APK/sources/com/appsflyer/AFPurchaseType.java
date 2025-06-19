package com.appsflyer;

import com.quizlet.db.billing.model.DBSubscription;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public enum AFPurchaseType {
    SUBSCRIPTION(DBSubscription.TABLE_NAME),
    ONE_TIME_PURCHASE("one_time_purchase");


    @NotNull
    private final String value;

    AFPurchaseType(String str) {
        this.value = str;
    }

    @NotNull
    public final String getValue() {
        return this.value;
    }
}
