package app.cash.sqldelight.driver.android;

import java.io.IOException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements j {
    public final androidx.sqlite.db.framework.i a;

    public b(androidx.sqlite.db.framework.i statement) {
        Intrinsics.checkNotNullParameter(statement, "statement");
        this.a = statement;
    }

    @Override // app.cash.sqldelight.driver.android.j
    public final long a() {
        return this.a.a();
    }

    @Override // app.cash.sqldelight.driver.android.j
    public final void b(int i, Long l) {
        androidx.sqlite.db.framework.i iVar = this.a;
        int i2 = i + 1;
        if (l == null) {
            iVar.R(i2);
        } else {
            iVar.z(i2, l.longValue());
        }
    }

    @Override // app.cash.sqldelight.driver.android.j
    public final Object c(Function1 mapper) {
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        throw new UnsupportedOperationException();
    }

    @Override // app.cash.sqldelight.driver.android.j
    public final void close() throws IOException {
        this.a.close();
    }

    @Override // app.cash.sqldelight.driver.android.j
    public final void g(int i, String str) {
        androidx.sqlite.db.framework.i iVar = this.a;
        int i2 = i + 1;
        if (str == null) {
            iVar.R(i2);
        } else {
            iVar.g(i2, str);
        }
    }
}
