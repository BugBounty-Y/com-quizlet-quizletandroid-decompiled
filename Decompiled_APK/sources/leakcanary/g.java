package leakcanary;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.I;
import androidx.fragment.app.J;
import androidx.fragment.app.S;
import java.lang.reflect.Proxy;
import java.util.concurrent.CopyOnWriteArrayList;
import kotlin.TypeCastException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements Application.ActivityLifecycleCallbacks {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ Application.ActivityLifecycleCallbacks b;
    public final /* synthetic */ Object c;

    public g(Application application) throws IllegalArgumentException {
        this.c = application;
        Object objNewProxyInstance = Proxy.newProxyInstance(Application.ActivityLifecycleCallbacks.class.getClassLoader(), new Class[]{Application.ActivityLifecycleCallbacks.class}, leakcanary.internal.e.a);
        if (objNewProxyInstance == null) {
            throw new TypeCastException("null cannot be cast to non-null type android.app.Application.ActivityLifecycleCallbacks");
        }
        this.b = (Application.ActivityLifecycleCallbacks) objNewProxyInstance;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity p0, Bundle bundle) {
        switch (this.a) {
            case 0:
                Intrinsics.f(p0, "p0");
                this.b.onActivityCreated(p0, bundle);
                break;
            default:
                Intrinsics.f(p0, "activity");
                com.quizlet.quizletandroid.ui.studymodes.match.fragment.t tVar = new com.quizlet.quizletandroid.ui.studymodes.match.fragment.t(this, 16);
                if (((Boolean) leakcanary.internal.c.a.getValue()).booleanValue() && (p0 instanceof I)) {
                    AbstractC1136h0 supportFragmentManager = ((I) p0).getSupportFragmentManager();
                    leakcanary.internal.b cb = new leakcanary.internal.b(tVar);
                    J j = supportFragmentManager.p;
                    j.getClass();
                    Intrinsics.checkNotNullParameter(cb, "cb");
                    ((CopyOnWriteArrayList) j.b).add(new S(cb));
                    break;
                }
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
        switch (this.a) {
            case 0:
                Intrinsics.f(activity, "activity");
                ((kotlin.jvm.internal.r) this.c).invoke(activity);
                break;
            default:
                Intrinsics.f(activity, "p0");
                this.b.onActivityDestroyed(activity);
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity p0) {
        switch (this.a) {
            case 0:
                Intrinsics.f(p0, "p0");
                this.b.onActivityPaused(p0);
                break;
            default:
                Intrinsics.f(p0, "p0");
                this.b.onActivityPaused(p0);
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity p0) {
        switch (this.a) {
            case 0:
                Intrinsics.f(p0, "p0");
                this.b.onActivityResumed(p0);
                break;
            default:
                Intrinsics.f(p0, "p0");
                this.b.onActivityResumed(p0);
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity p0, Bundle p1) {
        switch (this.a) {
            case 0:
                Intrinsics.f(p0, "p0");
                Intrinsics.f(p1, "p1");
                this.b.onActivitySaveInstanceState(p0, p1);
                break;
            default:
                Intrinsics.f(p0, "p0");
                Intrinsics.f(p1, "p1");
                this.b.onActivitySaveInstanceState(p0, p1);
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStarted(Activity p0) {
        switch (this.a) {
            case 0:
                Intrinsics.f(p0, "p0");
                this.b.onActivityStarted(p0);
                break;
            default:
                Intrinsics.f(p0, "p0");
                this.b.onActivityStarted(p0);
                break;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity p0) {
        switch (this.a) {
            case 0:
                Intrinsics.f(p0, "p0");
                this.b.onActivityStopped(p0);
                break;
            default:
                Intrinsics.f(p0, "p0");
                this.b.onActivityStopped(p0);
                break;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public g(Function1 function1) throws IllegalArgumentException {
        this.c = (kotlin.jvm.internal.r) function1;
        Object objNewProxyInstance = Proxy.newProxyInstance(Application.ActivityLifecycleCallbacks.class.getClassLoader(), new Class[]{Application.ActivityLifecycleCallbacks.class}, leakcanary.internal.e.a);
        if (objNewProxyInstance != null) {
            this.b = (Application.ActivityLifecycleCallbacks) objNewProxyInstance;
            return;
        }
        throw new TypeCastException("null cannot be cast to non-null type android.app.Application.ActivityLifecycleCallbacks");
    }
}
