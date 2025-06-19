package androidx.core.view;

import android.view.MenuItem;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;

/* renamed from: androidx.core.view.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1057n {
    public final Runnable a;
    public final CopyOnWriteArrayList b = new CopyOnWriteArrayList();
    public final HashMap c = new HashMap();

    public C1057n(Runnable runnable) {
        this.a = runnable;
    }

    public final boolean a(MenuItem menuItem) {
        Iterator it2 = this.b.iterator();
        while (it2.hasNext()) {
            if (((androidx.fragment.app.W) ((InterfaceC1058o) it2.next())).a.q(menuItem)) {
                return true;
            }
        }
        return false;
    }
}
