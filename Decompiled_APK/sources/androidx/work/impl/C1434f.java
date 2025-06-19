package androidx.work.impl;

import android.content.Context;
import android.database.SQLException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.work.impl.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1434f extends androidx.room.migration.a {
    public final Context c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1434f(Context mContext, int i, int i2) {
        super(i, i2);
        Intrinsics.checkNotNullParameter(mContext, "mContext");
        this.c = mContext;
    }

    @Override // androidx.room.migration.a
    public final void a(androidx.sqlite.db.framework.b db) throws SQLException {
        Intrinsics.checkNotNullParameter(db, "db");
        if (this.b >= 10) {
            db.l(new Object[]{"reschedule_needed", 1});
        } else {
            this.c.getSharedPreferences("androidx.work.util.preferences", 0).edit().putBoolean("reschedule_needed", true).apply();
        }
    }
}
