package androidx.lifecycle;

import android.app.Activity;
import android.app.Fragment;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.lifecycle.c0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1242c0 extends AbstractC1253n {
    final /* synthetic */ d0 this$0;

    /* renamed from: androidx.lifecycle.c0$a */
    public static final class a extends AbstractC1253n {
        final /* synthetic */ d0 this$0;

        public a(d0 d0Var) {
            this.this$0 = d0Var;
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPostResumed(Activity activity) {
            Intrinsics.checkNotNullParameter(activity, "activity");
            this.this$0.a();
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPostStarted(Activity activity) {
            Intrinsics.checkNotNullParameter(activity, "activity");
            d0 d0Var = this.this$0;
            int i = d0Var.a + 1;
            d0Var.a = i;
            if (i == 1 && d0Var.d) {
                d0Var.f.e(A.ON_START);
                d0Var.d = false;
            }
        }
    }

    public C1242c0(d0 d0Var) {
        this.this$0 = d0Var;
    }

    @Override // androidx.lifecycle.AbstractC1253n, android.app.Application.ActivityLifecycleCallbacks
    public void onActivityCreated(Activity activity, Bundle bundle) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        if (Build.VERSION.SDK_INT < 29) {
            int i = l0.b;
            Intrinsics.checkNotNullParameter(activity, "<this>");
            Fragment fragmentFindFragmentByTag = activity.getFragmentManager().findFragmentByTag("androidx.lifecycle.LifecycleDispatcher.report_fragment_tag");
            Intrinsics.e(fragmentFindFragmentByTag, "null cannot be cast to non-null type androidx.lifecycle.ReportFragment");
            ((l0) fragmentFindFragmentByTag).a = this.this$0.h;
        }
    }

    @Override // androidx.lifecycle.AbstractC1253n, android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPaused(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        d0 d0Var = this.this$0;
        int i = d0Var.b - 1;
        d0Var.b = i;
        if (i == 0) {
            Handler handler = d0Var.e;
            Intrinsics.d(handler);
            handler.postDelayed(d0Var.g, 700L);
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPreCreated(Activity activity, Bundle bundle) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        AbstractC1240b0.a(activity, new a(this.this$0));
    }

    @Override // androidx.lifecycle.AbstractC1253n, android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStopped(Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        d0 d0Var = this.this$0;
        int i = d0Var.a - 1;
        d0Var.a = i;
        if (i == 0 && d0Var.c) {
            d0Var.f.e(A.ON_STOP);
            d0Var.d = true;
        }
    }
}
