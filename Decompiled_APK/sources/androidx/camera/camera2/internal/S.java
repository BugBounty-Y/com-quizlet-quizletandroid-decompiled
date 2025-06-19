package androidx.camera.camera2.internal;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;

/* loaded from: classes.dex */
public final /* synthetic */ class S implements androidx.concurrent.futures.j {
    public final /* synthetic */ V a;

    public void a() {
        V v = this.a;
        synchronized (v.a) {
            try {
                if (v.i == 5) {
                    v.k(v.f);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.concurrent.futures.j
    public Object d(androidx.concurrent.futures.i iVar) {
        String str;
        V v = this.a;
        synchronized (v.a) {
            AbstractC3242q6.h("Release completer expected to be null", v.k == null);
            v.k = iVar;
            str = "Release[session=" + v + "]";
        }
        return str;
    }
}
