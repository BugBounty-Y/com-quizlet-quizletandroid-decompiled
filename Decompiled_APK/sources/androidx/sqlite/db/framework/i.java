package androidx.sqlite.db.framework;

import android.database.sqlite.SQLiteStatement;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i extends h implements androidx.sqlite.db.f {
    public final SQLiteStatement b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(SQLiteStatement delegate) {
        super(delegate);
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.b = delegate;
    }

    public final int a() {
        return this.b.executeUpdateDelete();
    }
}
