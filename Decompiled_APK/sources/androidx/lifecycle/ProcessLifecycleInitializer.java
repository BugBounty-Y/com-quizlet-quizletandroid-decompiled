package androidx.lifecycle;

import android.app.Application;
import android.content.Context;
import android.os.Handler;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class ProcessLifecycleInitializer implements androidx.startup.b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        androidx.startup.a aVarC = androidx.startup.a.c(context);
        Intrinsics.checkNotNullExpressionValue(aVarC, "getInstance(...)");
        if (!aVarC.b.contains(ProcessLifecycleInitializer.class)) {
            throw new IllegalStateException("ProcessLifecycleInitializer cannot be initialized lazily.\n               Please ensure that you have:\n               <meta-data\n                   android:name='androidx.lifecycle.ProcessLifecycleInitializer'\n                   android:value='androidx.startup' />\n               under InitializationProvider in your AndroidManifest.xml");
        }
        AtomicBoolean atomicBoolean = G.a;
        Intrinsics.checkNotNullParameter(context, "context");
        if (!G.a.getAndSet(true)) {
            Context applicationContext = context.getApplicationContext();
            Intrinsics.e(applicationContext, "null cannot be cast to non-null type android.app.Application");
            ((Application) applicationContext).registerActivityLifecycleCallbacks(new F());
        }
        d0 d0Var = d0.i;
        Intrinsics.checkNotNullParameter(context, "context");
        d0 d0Var2 = d0.i;
        d0Var2.getClass();
        Intrinsics.checkNotNullParameter(context, "context");
        d0Var2.e = new Handler();
        d0Var2.f.e(A.ON_CREATE);
        Context applicationContext2 = context.getApplicationContext();
        Intrinsics.e(applicationContext2, "null cannot be cast to non-null type android.app.Application");
        ((Application) applicationContext2).registerActivityLifecycleCallbacks(new C1242c0(d0Var2));
        return d0Var2;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return kotlin.collections.K.a;
    }
}
