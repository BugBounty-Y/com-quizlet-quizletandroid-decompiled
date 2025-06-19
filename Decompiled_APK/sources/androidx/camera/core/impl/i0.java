package androidx.camera.core.impl;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class i0 {
    public ArrayList a;

    public i0(List list) {
        this.a = new ArrayList(list);
    }

    public static void d(i0 i0Var) {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = i0Var.a.iterator();
        while (it2.hasNext()) {
            arrayList.add(((e0) it2.next()).getClass().getSimpleName());
        }
        String.join(" | ", arrayList);
    }

    public boolean a(Class cls) {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            if (cls.isAssignableFrom(((e0) it2.next()).getClass())) {
                return true;
            }
        }
        return false;
    }

    public e0 b(Class cls) {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            e0 e0Var = (e0) it2.next();
            if (e0Var.getClass() == cls) {
                return e0Var;
            }
        }
        return null;
    }

    public synchronized com.bumptech.glide.load.k c(Class cls) {
        int size = this.a.size();
        for (int i = 0; i < size; i++) {
            com.bumptech.glide.provider.d dVar = (com.bumptech.glide.provider.d) this.a.get(i);
            if (dVar.a.isAssignableFrom(cls)) {
                return dVar.b;
            }
        }
        return null;
    }
}
