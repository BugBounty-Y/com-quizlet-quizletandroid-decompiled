package androidx.recyclerview.widget;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;

/* renamed from: androidx.recyclerview.widget.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1364f {
    public static final ExecutorC1362e h = new ExecutorC1362e();
    public final C1356b a;
    public final N0 b;
    public List e;
    public int g;
    public final CopyOnWriteArrayList d = new CopyOnWriteArrayList();
    public List f = Collections.EMPTY_LIST;
    public final ExecutorC1362e c = h;

    public C1364f(C1356b c1356b, N0 n0) {
        this.a = c1356b;
        this.b = n0;
    }

    public final void a(Runnable runnable) {
        Iterator it2 = this.d.iterator();
        while (it2.hasNext()) {
            ((U) it2.next()).a.getClass();
        }
        if (runnable != null) {
            runnable.run();
        }
    }

    public final void b(List list, Runnable runnable) {
        int i = this.g + 1;
        this.g = i;
        List list2 = this.e;
        if (list == list2) {
            if (runnable != null) {
                runnable.run();
                return;
            }
            return;
        }
        C1356b c1356b = this.a;
        if (list == null) {
            int size = list2.size();
            this.e = null;
            this.f = Collections.EMPTY_LIST;
            c1356b.d(0, size);
            a(runnable);
            return;
        }
        if (list2 != null) {
            ((ExecutorService) this.b.a).execute(new androidx.fragment.app.y0(this, list2, list, i, runnable));
            return;
        }
        this.e = list;
        this.f = Collections.unmodifiableList(list);
        c1356b.c(0, list.size());
        a(runnable);
    }
}
