package androidx.sqlite.db.framework;

import android.database.sqlite.SQLiteProgram;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class h implements androidx.sqlite.db.f {
    public final SQLiteProgram a;

    public h(SQLiteProgram delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.a = delegate;
    }

    @Override // androidx.sqlite.db.f
    public final void E(int i, byte[] value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.a.bindBlob(i, value);
    }

    @Override // androidx.sqlite.db.f
    public final void R(int i) {
        this.a.bindNull(i);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        this.a.close();
    }

    @Override // androidx.sqlite.db.f
    public final void g(int i, String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.a.bindString(i, value);
    }

    @Override // androidx.sqlite.db.f
    public final void s(int i, double d) {
        this.a.bindDouble(i, d);
    }

    @Override // androidx.sqlite.db.f
    public final void z(int i, long j) {
        this.a.bindLong(i, j);
    }
}
