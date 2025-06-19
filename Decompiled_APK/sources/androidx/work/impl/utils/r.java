package androidx.work.impl.utils;

import androidx.work.impl.WorkDatabase;
import androidx.work.z;

/* loaded from: classes.dex */
public final class r {
    public static final String c = z.e("WorkProgressUpdater");
    public final WorkDatabase a;
    public final androidx.work.impl.utils.taskexecutor.c b;

    public r(WorkDatabase workDatabase, androidx.work.impl.utils.taskexecutor.c cVar) {
        this.a = workDatabase;
        this.b = cVar;
    }
}
