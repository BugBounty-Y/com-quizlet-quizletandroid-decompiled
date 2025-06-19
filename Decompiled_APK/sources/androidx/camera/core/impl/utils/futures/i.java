package androidx.camera.core.impl.utils.futures;

import androidx.appcompat.app.J;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;

/* loaded from: classes.dex */
public abstract class i {
    public static Object a(com.google.common.util.concurrent.e eVar) {
        AbstractC3242q6.h("Future was expected to be done, " + eVar, eVar.isDone());
        return b(eVar);
    }

    public static Object b(Future future) {
        Object obj;
        boolean z = false;
        while (true) {
            try {
                obj = future.get();
                break;
            } catch (InterruptedException unused) {
                z = true;
            } catch (Throwable th) {
                if (z) {
                    Thread.currentThread().interrupt();
                }
                throw th;
            }
        }
        if (z) {
            Thread.currentThread().interrupt();
        }
        return obj;
    }

    public static k c(Object obj) {
        return obj == null ? k.c : new k(obj, 0);
    }

    public static com.google.common.util.concurrent.e d(com.google.common.util.concurrent.e eVar) {
        eVar.getClass();
        return eVar.isDone() ? eVar : Y5.b(new g(1, eVar));
    }

    public static void e(boolean z, com.google.common.util.concurrent.e eVar, androidx.concurrent.futures.i iVar, androidx.camera.core.impl.utils.executor.a aVar) {
        eVar.getClass();
        iVar.getClass();
        aVar.getClass();
        eVar.a(new h(0, eVar, new com.google.android.gms.internal.instantapps.a(iVar, 7)), aVar);
        if (z) {
            iVar.a(new J(eVar, 5), T.a());
        }
    }

    public static b f(com.google.common.util.concurrent.e eVar, a aVar, Executor executor) {
        b bVar = new b(aVar, eVar);
        eVar.a(bVar, executor);
        return bVar;
    }
}
