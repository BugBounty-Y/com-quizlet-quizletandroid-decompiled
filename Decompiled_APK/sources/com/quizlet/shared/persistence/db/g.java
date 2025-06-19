package com.quizlet.shared.persistence.db;

import androidx.compose.animation.core.J0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends J0 {
    public final com.quizlet.data.repository.login.a c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(app.cash.sqldelight.driver.android.i driver, com.quizlet.data.repository.login.a dbStudiableMetadataAdapter) {
        super(driver);
        Intrinsics.checkNotNullParameter(driver, "driver");
        Intrinsics.checkNotNullParameter(dbStudiableMetadataAdapter, "dbStudiableMetadataAdapter");
        this.c = dbStudiableMetadataAdapter;
    }
}
