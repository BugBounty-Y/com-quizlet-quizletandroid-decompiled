package app.cash.sqldelight.driver.android;

import java.util.ArrayList;
import java.util.LinkedHashSet;

/* loaded from: classes.dex */
public final class e {
    public boolean f;
    public final e h;
    public final /* synthetic */ i i;
    public final long a = Thread.currentThread().getId();
    public final ArrayList b = new ArrayList();
    public final ArrayList c = new ArrayList();
    public final LinkedHashSet d = new LinkedHashSet();
    public final LinkedHashSet e = new LinkedHashSet();
    public boolean g = true;

    public e(i iVar, e eVar) {
        this.i = iVar;
        this.h = eVar;
    }

    public final void a() {
        if (this.a != Thread.currentThread().getId()) {
            throw new IllegalStateException("Transaction objects (`TransactionWithReturn` and `TransactionWithoutReturn`) must be used\nonly within the transaction lambda scope.");
        }
        boolean z = this.f && this.g;
        i iVar = this.i;
        e eVar = this.h;
        if (eVar == null) {
            if (z) {
                iVar.i().B();
                iVar.i().i();
            } else {
                iVar.i().i();
            }
        }
        iVar.b.set(eVar);
        app.cash.sqldelight.db.d.a.getClass();
        app.cash.sqldelight.db.b bVar = app.cash.sqldelight.db.b.a;
    }
}
