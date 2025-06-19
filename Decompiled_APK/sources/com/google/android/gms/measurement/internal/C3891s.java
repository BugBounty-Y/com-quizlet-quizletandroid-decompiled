package com.google.android.gms.measurement.internal;

/* renamed from: com.google.android.gms.measurement.internal.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3891s {
    public static final Object f = new Object();
    public final String a;
    public final r b;
    public final Object c;
    public final Object d = new Object();
    public volatile Object e = null;

    public /* synthetic */ C3891s(String str, Object obj, r rVar) {
        this.a = str;
        this.c = obj;
        this.b = rVar;
    }

    public final Object a(Object obj) {
        synchronized (this.d) {
        }
        if (obj != null) {
            return obj;
        }
        if (AbstractC3883n0.k == null) {
            return this.c;
        }
        synchronized (f) {
            try {
                if (com.google.android.material.shape.e.x()) {
                    return this.e == null ? this.c : this.e;
                }
                try {
                    for (C3891s c3891s : AbstractC3893t.a) {
                        if (com.google.android.material.shape.e.x()) {
                            throw new IllegalStateException("Refreshing flag cache must be done on a worker thread.");
                        }
                        Object objZza = null;
                        try {
                            r rVar = c3891s.b;
                            if (rVar != null) {
                                objZza = rVar.zza();
                            }
                        } catch (IllegalStateException unused) {
                        }
                        synchronized (f) {
                            c3891s.e = objZza;
                        }
                    }
                } catch (SecurityException unused2) {
                }
                r rVar2 = this.b;
                if (rVar2 != null) {
                    try {
                        return rVar2.zza();
                    } catch (IllegalStateException | SecurityException unused3) {
                    }
                }
                return this.c;
            } finally {
            }
        }
    }
}
