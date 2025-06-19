package androidx.work.impl;

import androidx.work.EnumC1440n;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* loaded from: classes.dex */
public abstract class G {
    public static final String a;

    static {
        String strE = androidx.work.z.e("WorkerWrapper");
        Intrinsics.checkNotNullExpressionValue(strE, "tagWithPrefix(\"WorkerWrapper\")");
        a = strE;
    }

    public static final Object a(com.google.common.util.concurrent.e eVar, androidx.work.y yVar, kotlin.coroutines.jvm.internal.i frame) {
        try {
            if (eVar.isDone()) {
                return b(eVar);
            }
            C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
            c5028l.r();
            eVar.a(new com.google.common.util.concurrent.d(eVar, c5028l), EnumC1440n.a);
            c5028l.u(new androidx.compose.ui.viewinterop.b(7, yVar, eVar));
            Object objQ = c5028l.q();
            if (objQ == kotlin.coroutines.intrinsics.a.a) {
                Intrinsics.checkNotNullParameter(frame, "frame");
            }
            return objQ;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            Intrinsics.d(cause);
            throw cause;
        }
    }

    public static final Object b(Future future) {
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
}
