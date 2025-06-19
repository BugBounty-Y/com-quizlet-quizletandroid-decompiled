package app.cash.sqldelight.driver.android;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d extends androidx.sqlite.db.b {
    public final app.cash.sqldelight.db.a[] c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(app.cash.sqldelight.db.a... callbacks) {
        super((int) 2, 0);
        com.quizlet.shared.persistence.db.persistencedatabase.b schema = com.quizlet.shared.persistence.db.persistencedatabase.b.a;
        Intrinsics.checkNotNullParameter(schema, "schema");
        Intrinsics.checkNotNullParameter(callbacks, "callbacks");
        this.c = callbacks;
    }

    @Override // androidx.sqlite.db.b
    public final void m(androidx.sqlite.db.framework.b db) {
        Intrinsics.checkNotNullParameter(db, "db");
        i driver = new i(db);
        Intrinsics.checkNotNullParameter(driver, "driver");
        driver.a(null, "CREATE TABLE dbStudiableMetadata (\n    studiableMetadataType INTEGER NOT NULL,\n    studiableContainerId INTEGER NOT NULL,\n    studiableContainerType INTEGER NOT NULL,\n    model TEXT,\n    PRIMARY KEY (studiableMetadataType, studiableContainerId, studiableContainerType)\n)", null);
        app.cash.sqldelight.db.d.a.getClass();
        app.cash.sqldelight.db.b bVar = app.cash.sqldelight.db.b.a;
    }

    @Override // androidx.sqlite.db.b
    public final void p(androidx.sqlite.db.framework.b db, int i, int i2) {
        Intrinsics.checkNotNullParameter(db, "db");
        com.quizlet.shared.persistence.db.persistencedatabase.b.a.a(new i(db), i, i2, (app.cash.sqldelight.db.a[]) Arrays.copyOf(this.c, 0));
    }
}
