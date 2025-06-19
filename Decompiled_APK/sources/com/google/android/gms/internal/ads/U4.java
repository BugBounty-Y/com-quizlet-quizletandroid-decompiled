package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public final class U4 implements Application.ActivityLifecycleCallbacks {
    public final Application b;
    public final WeakReference c;
    public final /* synthetic */ int a = 1;
    public boolean d = false;

    public U4(Application application, ViewOnAttachStateChangeListenerC1952d5 viewOnAttachStateChangeListenerC1952d5) {
        this.c = new WeakReference(viewOnAttachStateChangeListenerC1952d5);
        this.b = application;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity activity, Bundle bundle) {
        switch (this.a) {
            case 0:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks != null) {
                        activityLifecycleCallbacks.onActivityCreated(activity, bundle);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception unused) {
                    return;
                }
            default:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks2 = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks2 != null) {
                        activityLifecycleCallbacks2.onActivityCreated(activity, bundle);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error while dispatching lifecycle callback.", e);
                    return;
                }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
        switch (this.a) {
            case 0:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks != null) {
                        activityLifecycleCallbacks.onActivityDestroyed(activity);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception unused) {
                    return;
                }
            default:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks2 = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks2 != null) {
                        activityLifecycleCallbacks2.onActivityDestroyed(activity);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error while dispatching lifecycle callback.", e);
                    return;
                }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity activity) {
        switch (this.a) {
            case 0:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks != null) {
                        activityLifecycleCallbacks.onActivityPaused(activity);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception unused) {
                    return;
                }
            default:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks2 = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks2 != null) {
                        activityLifecycleCallbacks2.onActivityPaused(activity);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error while dispatching lifecycle callback.", e);
                    return;
                }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity activity) {
        switch (this.a) {
            case 0:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks != null) {
                        activityLifecycleCallbacks.onActivityResumed(activity);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception unused) {
                    return;
                }
            default:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks2 = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks2 != null) {
                        activityLifecycleCallbacks2.onActivityResumed(activity);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error while dispatching lifecycle callback.", e);
                    return;
                }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
        switch (this.a) {
            case 0:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks != null) {
                        activityLifecycleCallbacks.onActivitySaveInstanceState(activity, bundle);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception unused) {
                    return;
                }
            default:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks2 = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks2 != null) {
                        activityLifecycleCallbacks2.onActivitySaveInstanceState(activity, bundle);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error while dispatching lifecycle callback.", e);
                    return;
                }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStarted(Activity activity) {
        switch (this.a) {
            case 0:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks != null) {
                        activityLifecycleCallbacks.onActivityStarted(activity);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception unused) {
                    return;
                }
            default:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks2 = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks2 != null) {
                        activityLifecycleCallbacks2.onActivityStarted(activity);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error while dispatching lifecycle callback.", e);
                    return;
                }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity activity) {
        switch (this.a) {
            case 0:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks != null) {
                        activityLifecycleCallbacks.onActivityStopped(activity);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception unused) {
                    return;
                }
            default:
                try {
                    Application.ActivityLifecycleCallbacks activityLifecycleCallbacks2 = (Application.ActivityLifecycleCallbacks) this.c.get();
                    if (activityLifecycleCallbacks2 != null) {
                        activityLifecycleCallbacks2.onActivityStopped(activity);
                    } else if (!this.d) {
                        this.b.unregisterActivityLifecycleCallbacks(this);
                        this.d = true;
                    }
                    break;
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error while dispatching lifecycle callback.", e);
                    return;
                }
        }
    }

    public U4(Application application, F5 f5) {
        this.c = new WeakReference(f5);
        this.b = application;
    }
}
