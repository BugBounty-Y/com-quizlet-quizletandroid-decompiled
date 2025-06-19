package androidx.concurrent.futures;

import com.google.android.gms.internal.mlkit_vision_barcode.X5;

/* loaded from: classes.dex */
public final class f extends X5 {
    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X5
    public final boolean a(h hVar, d dVar, d dVar2) {
        synchronized (hVar) {
            try {
                if (hVar.b != dVar) {
                    return false;
                }
                hVar.b = dVar2;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X5
    public final boolean b(h hVar, Object obj, Object obj2) {
        synchronized (hVar) {
            try {
                if (hVar.a != obj) {
                    return false;
                }
                hVar.a = obj2;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X5
    public final boolean c(h hVar, g gVar, g gVar2) {
        synchronized (hVar) {
            try {
                if (hVar.c != gVar) {
                    return false;
                }
                hVar.c = gVar2;
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X5
    public final void d(g gVar, g gVar2) {
        gVar.b = gVar2;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X5
    public final void e(g gVar, Thread thread) {
        gVar.a = thread;
    }
}
