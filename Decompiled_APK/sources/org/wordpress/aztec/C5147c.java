package org.wordpress.aztec;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: org.wordpress.aztec.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5147c {
    public final ArrayList a = new ArrayList();

    public final void a() {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            if (((WeakReference) it2.next()).get() != null) {
                throw new ClassCastException();
            }
            it2.remove();
        }
    }
}
