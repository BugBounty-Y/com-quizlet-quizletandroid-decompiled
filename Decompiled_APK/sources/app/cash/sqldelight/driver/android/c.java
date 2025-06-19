package app.cash.sqldelight.driver.android;

import android.database.Cursor;
import androidx.compose.foundation.lazy.u;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements androidx.sqlite.db.g, j {
    public final String a;
    public final androidx.sqlite.db.framework.b b;
    public final ArrayList c;

    public c(String sql, androidx.sqlite.db.framework.b database, int i) {
        Intrinsics.checkNotNullParameter(sql, "sql");
        Intrinsics.checkNotNullParameter(database, "database");
        this.a = sql;
        this.b = database;
        ArrayList arrayList = new ArrayList(i);
        for (int i2 = 0; i2 < i; i2++) {
            arrayList.add(null);
        }
        this.c = arrayList;
    }

    @Override // app.cash.sqldelight.driver.android.j
    public final long a() {
        throw new UnsupportedOperationException();
    }

    @Override // app.cash.sqldelight.driver.android.j
    public final void b(int i, Long l) {
        this.c.set(i, new u(l, i, 5));
    }

    @Override // app.cash.sqldelight.driver.android.j
    public final Object c(Function1 mapper) throws IOException {
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Cursor cursorR = this.b.r(this);
        try {
            Object obj = ((app.cash.sqldelight.db.c) ((app.cash.sqldelight.db.d) mapper.invoke(new a(cursorR)))).b;
            cursorR.close();
            return obj;
        } finally {
        }
    }

    @Override // app.cash.sqldelight.driver.android.j
    public final void close() {
    }

    @Override // androidx.sqlite.db.g
    public final String d() {
        return this.a;
    }

    @Override // androidx.sqlite.db.g
    public final void f(androidx.sqlite.db.f statement) {
        Intrinsics.checkNotNullParameter(statement, "statement");
        Iterator it2 = this.c.iterator();
        while (it2.hasNext()) {
            Function1 function1 = (Function1) it2.next();
            Intrinsics.d(function1);
            function1.invoke(statement);
        }
    }

    @Override // app.cash.sqldelight.driver.android.j
    public final void g(int i, String str) {
        this.c.set(i, new u(str, i, 6));
    }

    public final String toString() {
        return this.a;
    }
}
