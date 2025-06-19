package com.google.android.gms.internal.measurement;

import androidx.collection.C0207e;
import androidx.collection.C0208f;
import java.util.Iterator;

/* loaded from: classes2.dex */
public abstract class G1 {
    public static final C0208f a = new C0208f(0);

    public static synchronized void a() {
        C0208f c0208f = a;
        Iterator it2 = ((C0207e) c0208f.values()).iterator();
        if (it2.hasNext()) {
            ((G1) it2.next()).getClass();
            throw null;
        }
        c0208f.clear();
    }
}
