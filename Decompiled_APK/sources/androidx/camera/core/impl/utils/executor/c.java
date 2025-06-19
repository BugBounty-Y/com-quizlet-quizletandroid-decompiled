package androidx.camera.core.impl.utils.executor;

import android.view.View;
import com.google.android.gms.measurement.internal.BinderC3869g0;
import com.google.android.gms.measurement.internal.zzbh;
import java.lang.ref.WeakReference;
import java.util.concurrent.Callable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements Callable {
    public final /* synthetic */ int a;
    public final Object b;

    public c(BinderC3869g0 binderC3869g0, zzbh zzbhVar, String str) {
        this.a = 14;
        this.b = binderC3869g0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:221:0x039f  */
    /* JADX WARN: Removed duplicated region for block: B:268:0x035e A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // java.util.concurrent.Callable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object call() throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1136
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.core.impl.utils.executor.c.call():java.lang.Object");
    }

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public c(View rootView) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(rootView, "rootView");
        this.b = new WeakReference(rootView);
    }
}
