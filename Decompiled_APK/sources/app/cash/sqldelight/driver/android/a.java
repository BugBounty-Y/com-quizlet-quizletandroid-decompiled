package app.cash.sqldelight.driver.android;

import android.database.Cursor;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final Cursor a;

    public a(Cursor cursor) {
        Intrinsics.checkNotNullParameter(cursor, "cursor");
        this.a = cursor;
    }
}
