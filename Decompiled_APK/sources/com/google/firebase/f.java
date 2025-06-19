package com.google.firebase;

import com.google.android.gms.common.api.internal.InterfaceC1644b;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class f implements InterfaceC1644b {
    public static final AtomicReference a = new AtomicReference();

    @Override // com.google.android.gms.common.api.internal.InterfaceC1644b
    public final void a(boolean z) {
        synchronized (h.k) {
            try {
                Iterator it2 = new ArrayList(h.l.values()).iterator();
                while (it2.hasNext()) {
                    h hVar = (h) it2.next();
                    if (hVar.e.get()) {
                        Iterator it3 = hVar.i.iterator();
                        while (it3.hasNext()) {
                            h hVar2 = ((e) it3.next()).a;
                            if (z) {
                                hVar2.getClass();
                            } else {
                                ((com.google.firebase.heartbeatinfo.d) hVar2.h.get()).b();
                            }
                        }
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
