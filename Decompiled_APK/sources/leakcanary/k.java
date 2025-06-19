package leakcanary;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.view.inputmethod.InputMethodManager;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements Application.ActivityLifecycleCallbacks {
    public final /* synthetic */ Application.ActivityLifecycleCallbacks a;
    public final /* synthetic */ m b;
    public final /* synthetic */ Field c;
    public final /* synthetic */ InputMethodManager d;

    public k(m mVar, Field field, InputMethodManager inputMethodManager) throws IllegalArgumentException {
        this.b = mVar;
        this.c = field;
        this.d = inputMethodManager;
        Object objNewProxyInstance = Proxy.newProxyInstance(Application.ActivityLifecycleCallbacks.class.getClassLoader(), new Class[]{Application.ActivityLifecycleCallbacks.class}, leakcanary.internal.e.a);
        if (objNewProxyInstance == null) {
            throw new TypeCastException("null cannot be cast to non-null type android.app.Application.ActivityLifecycleCallbacks");
        }
        this.a = (Application.ActivityLifecycleCallbacks) objNewProxyInstance;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity p0, Bundle bundle) {
        Intrinsics.f(p0, "p0");
        this.a.onActivityCreated(p0, bundle);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x002a  */
    @Override // android.app.Application.ActivityLifecycleCallbacks
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onActivityDestroyed(android.app.Activity r10) {
        /*
            r9 = this;
            android.view.inputmethod.InputMethodManager r0 = r9.d
            java.lang.reflect.Field r1 = r9.c
            java.lang.String r2 = "activity"
            kotlin.jvm.internal.Intrinsics.f(r10, r2)
            java.lang.Object r2 = r1.get(r0)     // Catch: java.lang.Throwable -> L64
            android.view.View r2 = (android.view.View) r2     // Catch: java.lang.Throwable -> L64
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L2a
            android.view.Window r5 = r10.getWindow()     // Catch: java.lang.Throwable -> L64
            if (r5 == 0) goto L2a
            android.view.Window r5 = r10.getWindow()     // Catch: java.lang.Throwable -> L64
            java.lang.String r6 = "activity.window"
            kotlin.jvm.internal.Intrinsics.c(r5, r6)     // Catch: java.lang.Throwable -> L64
            android.view.View r5 = r5.getDecorView()     // Catch: java.lang.Throwable -> L64
            if (r5 != r2) goto L2a
            r5 = r4
            goto L2b
        L2a:
            r5 = r3
        L2b:
            r6 = 0
            if (r2 == 0) goto L59
            android.content.Context r2 = r2.getContext()     // Catch: java.lang.Throwable -> L64
            if (r2 == 0) goto L59
            leakcanary.m r7 = r9.b     // Catch: java.lang.Throwable -> L64
            r7.getClass()     // Catch: java.lang.Throwable -> L64
            r7 = r2
        L3a:
            boolean r8 = r7 instanceof android.app.Application     // Catch: java.lang.Throwable -> L64
            if (r8 == 0) goto L3f
            goto L59
        L3f:
            boolean r8 = r7 instanceof android.app.Activity     // Catch: java.lang.Throwable -> L64
            if (r8 == 0) goto L46
            android.app.Activity r7 = (android.app.Activity) r7     // Catch: java.lang.Throwable -> L64
            goto L5a
        L46:
            boolean r8 = r7 instanceof android.content.ContextWrapper     // Catch: java.lang.Throwable -> L64
            if (r8 == 0) goto L59
            android.content.ContextWrapper r7 = (android.content.ContextWrapper) r7     // Catch: java.lang.Throwable -> L64
            android.content.Context r7 = r7.getBaseContext()     // Catch: java.lang.Throwable -> L64
            if (r7 != r2) goto L53
            goto L59
        L53:
            java.lang.String r8 = "baseContext"
            kotlin.jvm.internal.Intrinsics.c(r7, r8)     // Catch: java.lang.Throwable -> L64
            goto L3a
        L59:
            r7 = r6
        L5a:
            if (r7 != r10) goto L5d
            r3 = r4
        L5d:
            if (r5 != 0) goto L61
            if (r3 == 0) goto L64
        L61:
            r1.set(r0, r6)     // Catch: java.lang.Throwable -> L64
        L64:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: leakcanary.k.onActivityDestroyed(android.app.Activity):void");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity p0) {
        Intrinsics.f(p0, "p0");
        this.a.onActivityPaused(p0);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity p0) {
        Intrinsics.f(p0, "p0");
        this.a.onActivityResumed(p0);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity p0, Bundle p1) {
        Intrinsics.f(p0, "p0");
        Intrinsics.f(p1, "p1");
        this.a.onActivitySaveInstanceState(p0, p1);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStarted(Activity p0) {
        Intrinsics.f(p0, "p0");
        this.a.onActivityStarted(p0);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity p0) {
        Intrinsics.f(p0, "p0");
        this.a.onActivityStopped(p0);
    }
}
