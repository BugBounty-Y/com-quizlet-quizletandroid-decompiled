package com.snowplowanalytics.core.emitter.storage;

import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import com.snowplowanalytics.core.tracker.e;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends SQLiteOpenHelper {
    public static final com.quizlet.quizletandroid.ui.common.images.capture.a a = new com.quizlet.quizletandroid.ui.common.images.capture.a();
    public static final HashMap b = new HashMap();

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onCreate(SQLiteDatabase database) throws SQLException {
        Intrinsics.checkNotNullParameter(database, "database");
        database.execSQL("CREATE TABLE IF NOT EXISTS 'events' (id INTEGER PRIMARY KEY, eventData BLOB, dateCreated TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onUpgrade(SQLiteDatabase database, int i, int i2) throws SQLException {
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullExpressionValue("com.snowplowanalytics.core.emitter.storage.a", "TAG");
        e.a("com.snowplowanalytics.core.emitter.storage.a", "Upgrade not implemented, resetting database...", new Object[0]);
        database.execSQL("DROP TABLE IF EXISTS 'events'");
        onCreate(database);
    }
}
