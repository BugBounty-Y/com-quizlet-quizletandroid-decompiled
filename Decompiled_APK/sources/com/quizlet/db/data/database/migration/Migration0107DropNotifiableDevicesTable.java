package com.quizlet.db.data.database.migration;

import com.quizlet.android.migrator.migrations.c;
import com.quizlet.android.migrator.migrations.changes.b;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class Migration0107DropNotifiableDevicesTable extends c {
    @Override // com.quizlet.android.migrator.migrations.b
    public com.quizlet.android.migrator.migrations.changes.c getChange() {
        return new b("notifiable_device");
    }
}
