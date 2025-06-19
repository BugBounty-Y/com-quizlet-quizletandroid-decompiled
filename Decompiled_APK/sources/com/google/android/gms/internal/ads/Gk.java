package com.google.android.gms.internal.ads;

import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArraySet;

/* loaded from: classes2.dex */
public final /* synthetic */ class Gk implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ Gk(Object obj, int i, Object obj2, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
        this.d = obj2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Iterator it2 = ((CopyOnWriteArraySet) this.c).iterator();
                while (it2.hasNext()) {
                    C2407nl c2407nl = (C2407nl) it2.next();
                    if (!c2407nl.d) {
                        int i = this.b;
                        if (i != -1) {
                            c2407nl.b.L(i);
                        }
                        c2407nl.c = true;
                        ((Pk) this.d).mo10b(c2407nl.a);
                    }
                }
                break;
            default:
                ((Av) this.c).w(this.b, (com.google.common.util.concurrent.e) this.d);
                break;
        }
    }
}
