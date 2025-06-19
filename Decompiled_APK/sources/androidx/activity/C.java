package androidx.activity;

import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class C {
    public final Object a;
    public boolean b;
    public final ArrayList c;

    public C(InterfaceExecutorC0040l executor, q reportFullyDrawn) {
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(reportFullyDrawn, "reportFullyDrawn");
        this.a = new Object();
        this.c = new ArrayList();
    }

    public final void a() {
        synchronized (this.a) {
            try {
                this.b = true;
                Iterator it2 = this.c.iterator();
                while (it2.hasNext()) {
                    ((Function0) it2.next()).invoke();
                }
                this.c.clear();
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
