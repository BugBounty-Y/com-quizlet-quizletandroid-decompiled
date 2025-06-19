package androidx.work.impl.utils;

import androidx.work.impl.C1433e;
import androidx.work.impl.WorkDatabase;
import androidx.work.z;

/* loaded from: classes.dex */
public final class p {
    public final androidx.work.impl.utils.taskexecutor.c a;
    public final C1433e b;
    public final androidx.work.impl.model.t c;

    static {
        z.e("WMFgUpdater");
    }

    public p(WorkDatabase workDatabase, C1433e c1433e, androidx.work.impl.utils.taskexecutor.c cVar) {
        this.b = c1433e;
        this.a = cVar;
        this.c = workDatabase.u();
    }
}
