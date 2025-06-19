package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class BC implements HC, InterfaceC2907zC {
    public static final Object c = new Object();
    public volatile HC a;
    public volatile Object b = c;

    public BC(HC hc) {
        this.a = hc;
    }

    public static InterfaceC2907zC a(HC hc) {
        return hc instanceof InterfaceC2907zC ? (InterfaceC2907zC) hc : new BC(hc);
    }

    public static BC b(HC hc) {
        return hc instanceof BC ? (BC) hc : new BC(hc);
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        Object obj = this.b;
        Object obj2 = c;
        if (obj != obj2) {
            return obj;
        }
        synchronized (this) {
            try {
                Object obj3 = this.b;
                if (obj3 != obj2) {
                    return obj3;
                }
                Object objZzb = this.a.zzb();
                Object obj4 = this.b;
                if (obj4 != obj2 && obj4 != objZzb) {
                    throw new IllegalStateException("Scoped provider was invoked recursively returning different results: " + obj4 + " & " + objZzb + ". This is likely due to a circular dependency.");
                }
                this.b = objZzb;
                this.a = null;
                return objZzb;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
