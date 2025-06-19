package com.quizlet.shared.persistence.db.persistencedatabase;

import androidx.compose.animation.core.J0;
import app.cash.sqldelight.driver.android.i;
import com.quizlet.shared.persistence.db.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends J0 {
    public final g c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(i driver, com.quizlet.data.repository.login.a dbStudiableMetadataAdapter) {
        super(driver);
        Intrinsics.checkNotNullParameter(driver, "driver");
        Intrinsics.checkNotNullParameter(dbStudiableMetadataAdapter, "dbStudiableMetadataAdapter");
        this.c = new g(driver, dbStudiableMetadataAdapter);
    }
}
