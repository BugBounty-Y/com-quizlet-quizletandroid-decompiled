package app.cash.sqldelight.driver.android;

import androidx.compose.animation.core.C0268t0;
import java.io.Closeable;
import java.io.IOException;
import java.util.LinkedHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes.dex */
public final class i implements Closeable {
    public final androidx.sqlite.db.e a;
    public final ThreadLocal b;
    public final u c;
    public final h d;
    public final LinkedHashMap e;

    public i(androidx.sqlite.db.e eVar, androidx.sqlite.db.framework.b bVar, int i) {
        this.a = eVar;
        if (!((eVar != null) ^ (bVar != null))) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        this.b = new ThreadLocal();
        this.c = l.b(new androidx.credentials.playservices.controllers.BeginSignIn.d(15, this, bVar));
        this.d = new h(i);
        this.e = new LinkedHashMap();
    }

    public final app.cash.sqldelight.db.c a(Integer num, String sql, Function1 function1) {
        Intrinsics.checkNotNullParameter(sql, "sql");
        return new app.cash.sqldelight.db.c(d(num, new androidx.credentials.playservices.controllers.BeginSignIn.d(16, this, sql), function1, f.a));
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        Unit unit;
        this.d.evictAll();
        androidx.sqlite.db.e eVar = this.a;
        if (eVar != null) {
            eVar.close();
            unit = Unit.a;
        } else {
            unit = null;
        }
        if (unit == null) {
            i().close();
        }
    }

    public final Object d(Integer num, Function0 function0, Function1 function1, Function1 function12) {
        h hVar = this.d;
        j jVar = num != null ? (j) hVar.remove(num) : null;
        if (jVar == null) {
            jVar = (j) function0.invoke();
        }
        if (function1 != null) {
            try {
                function1.invoke(jVar);
            } catch (Throwable th) {
                if (num != null) {
                    j jVar2 = (j) hVar.put(num, jVar);
                    if (jVar2 != null) {
                        jVar2.close();
                    }
                } else {
                    jVar.close();
                }
                throw th;
            }
        }
        Object objInvoke = function12.invoke(jVar);
        if (num == null) {
            jVar.close();
            return objInvoke;
        }
        j jVar3 = (j) hVar.put(num, jVar);
        if (jVar3 != null) {
            jVar3.close();
        }
        return objInvoke;
    }

    public final app.cash.sqldelight.db.c f(Integer num, String sql, Function1 mapper, int i, Function1 function1) {
        Intrinsics.checkNotNullParameter(sql, "sql");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        return new app.cash.sqldelight.db.c(d(num, new g(sql, this, i), function1, new C0268t0(3, mapper)));
    }

    public final androidx.sqlite.db.framework.b i() {
        return (androidx.sqlite.db.framework.b) this.c.getValue();
    }

    public /* synthetic */ i(androidx.sqlite.db.framework.b bVar) {
        this(null, bVar, 1);
    }
}
