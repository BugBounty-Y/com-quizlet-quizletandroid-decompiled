package com.quizlet.shared.persistence.db.persistencedatabase;

import app.cash.sqldelight.db.d;
import app.cash.sqldelight.driver.android.i;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public static final b a = new b();

    public final app.cash.sqldelight.db.c a(i driver, long j, long j2, app.cash.sqldelight.db.a[] callbacks) {
        Intrinsics.checkNotNullParameter(driver, "driver");
        Intrinsics.checkNotNullParameter(callbacks, "callbacks");
        ArrayList arrayList = new ArrayList();
        if (callbacks.length > 0) {
            app.cash.sqldelight.db.a aVar = callbacks[0];
            throw null;
        }
        Iterator it2 = CollectionsKt.n0(arrayList, new a()).iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
        if (j < j2) {
            if (j <= 1 && j2 > 1) {
                driver.a(null, "CREATE TABLE dbStudiableMetadata (\n    studiableMetadataType INTEGER NOT NULL,\n    studiableContainerId INTEGER NOT NULL,\n    studiableContainerType INTEGER NOT NULL,\n    model TEXT,\n    PRIMARY KEY (studiableMetadataType, studiableContainerId, studiableContainerType)\n)", null);
            }
            d.a.getClass();
            app.cash.sqldelight.db.b bVar = app.cash.sqldelight.db.b.a;
        }
        d.a.getClass();
        return new app.cash.sqldelight.db.c(app.cash.sqldelight.db.b.b);
    }
}
