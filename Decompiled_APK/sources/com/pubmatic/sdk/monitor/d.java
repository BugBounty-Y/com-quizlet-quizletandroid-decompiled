package com.pubmatic.sdk.monitor;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public class d implements Application.ActivityLifecycleCallbacks {
    private c a;
    private Application b;
    private boolean c = false;
    public WeakReference<Activity> currentActivity;

    public d(Application application) {
        this.b = application;
    }

    public Activity getCurrentActivity() {
        WeakReference<Activity> weakReference = this.currentActivity;
        if (weakReference != null) {
            return weakReference.get();
        }
        return null;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityCreated(Activity activity, Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityDestroyed(Activity activity) {
        c cVar;
        if (!this.c && (cVar = this.a) != null) {
            cVar.a(activity);
        }
        WeakReference<Activity> weakReference = this.currentActivity;
        if (weakReference != null) {
            weakReference.clear();
        }
        this.currentActivity = null;
        this.c = false;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPaused(Activity activity) {
        c cVar = this.a;
        if (cVar != null) {
            cVar.onActivityPaused(activity);
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityResumed(Activity activity) {
        this.currentActivity = new WeakReference<>(activity);
        c cVar = this.a;
        if (cVar != null) {
            cVar.onActivityResumed(activity);
        }
        this.c = true;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStarted(Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStopped(Activity activity) {
    }

    public void reset() {
        this.b.unregisterActivityLifecycleCallbacks(this);
        this.currentActivity = null;
    }

    public void start(c cVar) {
        this.a = cVar;
        this.b.registerActivityLifecycleCallbacks(this);
    }
}
