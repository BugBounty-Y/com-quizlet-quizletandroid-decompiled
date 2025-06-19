package androidx.compose.runtime;

import androidx.work.impl.WorkDatabase;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.j256.ormlite.support.ConnectionSource;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.runtime.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0772a implements InterfaceC0790d {
    public final Object a;
    public Object b;
    public final Object c;

    public AbstractC0772a(OrmLiteSqliteOpenHelper ormLiteSqliteOpenHelper, ConnectionSource connectionSource, com.google.firebase.messaging.p pVar) {
        this.a = ormLiteSqliteOpenHelper;
        this.b = connectionSource;
        this.c = pVar;
    }

    public androidx.sqlite.db.framework.i a() {
        ((WorkDatabase) this.a).a();
        return ((AtomicBoolean) this.b).compareAndSet(false, true) ? (androidx.sqlite.db.framework.i) ((kotlin.u) this.c).getValue() : g();
    }

    public void b() {
        ((ArrayList) this.c).clear();
        this.b = this.a;
        m();
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public void d(Object obj) {
        ((ArrayList) this.c).add(this.b);
        this.b = obj;
    }

    public androidx.sqlite.db.framework.i g() {
        String sql = j();
        WorkDatabase workDatabase = (WorkDatabase) this.a;
        workDatabase.getClass();
        Intrinsics.checkNotNullParameter(sql, "sql");
        workDatabase.a();
        workDatabase.b();
        return workDatabase.h().I().f(sql);
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public void h() {
        this.b = ((ArrayList) this.c).remove(r0.size() - 1);
    }

    public abstract String j();

    @Override // androidx.compose.runtime.InterfaceC0790d
    public Object l() {
        return this.b;
    }

    public abstract void m();

    public void n(androidx.sqlite.db.framework.i statement) {
        Intrinsics.checkNotNullParameter(statement, "statement");
        if (statement == ((androidx.sqlite.db.framework.i) ((kotlin.u) this.c).getValue())) {
            ((AtomicBoolean) this.b).set(false);
        }
    }

    public AbstractC0772a(WorkDatabase database) {
        Intrinsics.checkNotNullParameter(database, "database");
        this.a = database;
        this.b = new AtomicBoolean(false);
        this.c = kotlin.l.b(new androidx.compose.ui.input.nestedscroll.b(this, 27));
    }

    public AbstractC0772a(Object obj) {
        this.a = obj;
        this.c = new ArrayList();
        this.b = obj;
    }
}
