package androidx.work.impl.diagnostics;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import androidx.work.C;
import androidx.work.D;
import androidx.work.impl.r;
import androidx.work.impl.workers.DiagnosticsWorker;
import androidx.work.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class DiagnosticsReceiver extends BroadcastReceiver {
    public static final String a = z.e("DiagnosticsRcvr");

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }
        z.c().getClass();
        try {
            Intrinsics.checkNotNullParameter(context, "context");
            r rVarH = r.h(context);
            Intrinsics.checkNotNullExpressionValue(rVarH, "getInstance(context)");
            Intrinsics.checkNotNullParameter(DiagnosticsWorker.class, "workerClass");
            Intrinsics.checkNotNullParameter(DiagnosticsWorker.class, "workerClass");
            rVarH.b((D) new C(DiagnosticsWorker.class).a());
        } catch (IllegalStateException e) {
            z.c().b(a, "WorkManager is not initialized", e);
        }
    }
}
