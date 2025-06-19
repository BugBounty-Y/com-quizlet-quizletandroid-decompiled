package com.braze.lrucache;

import java.util.Map;
import java.util.concurrent.Callable;

/* loaded from: classes.dex */
public final class a implements Callable {
    public final /* synthetic */ f a;

    public a(f fVar) {
        this.a = fVar;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        synchronized (this.a) {
            try {
                f fVar = this.a;
                if (fVar.i == null) {
                    return null;
                }
                while (fVar.h > fVar.f) {
                    fVar.d((String) ((Map.Entry) fVar.j.entrySet().iterator().next()).getKey());
                }
                if (this.a.a()) {
                    this.a.d();
                    this.a.k = 0;
                }
                return null;
            } finally {
            }
        }
    }
}
