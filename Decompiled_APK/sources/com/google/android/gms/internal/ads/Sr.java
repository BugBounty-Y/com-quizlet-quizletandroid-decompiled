package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.Application;
import android.os.Bundle;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

/* loaded from: classes2.dex */
public class Sr implements Application.ActivityLifecycleCallbacks {
    public final /* synthetic */ int a;
    public boolean b;
    public boolean c;
    public Object d;

    private final void e(Activity activity, Bundle bundle) {
    }

    private final void f(Activity activity, Bundle bundle) {
    }

    private final void g(Activity activity, Bundle bundle) {
    }

    private final void h(Activity activity) {
    }

    private final void i(Activity activity) {
    }

    private final void j(Activity activity) {
    }

    private final void k(Activity activity) {
    }

    private final void l(Activity activity) {
    }

    private final void m(Activity activity) {
    }

    private final void n(Activity activity) {
    }

    private final void o(Activity activity) {
    }

    private final void p(Activity activity) {
    }

    private final void q(Activity activity, Bundle bundle) {
    }

    private final void r(Activity activity, Bundle bundle) {
    }

    private final void s(Activity activity, Bundle bundle) {
    }

    public void a() {
    }

    public void b(boolean z) {
    }

    public void c() {
    }

    public boolean d() {
        return false;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity activity, Bundle bundle) {
        int i = this.a;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
        int i = this.a;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity activity) {
        int i = this.a;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity activity) {
        int i = this.a;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
        int i = this.a;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStarted(Activity activity) {
        switch (this.a) {
            case 0:
                if (!this.c) {
                    this.c = true;
                    if (this.b) {
                        t(true);
                        Rr rr = (Rr) this.d;
                        if (rr != null) {
                            rr.a(true);
                            return;
                        }
                        return;
                    }
                    return;
                }
                return;
            case 1:
                if (!this.c) {
                    this.c = true;
                    if (this.b) {
                        b(true);
                        com.iab.omid.library.amazon.internal.d dVar = (com.iab.omid.library.amazon.internal.d) this.d;
                        if (dVar != null) {
                            dVar.a(true);
                            return;
                        }
                        return;
                    }
                    return;
                }
                return;
            default:
                if (!this.c) {
                    this.c = true;
                    if (this.b) {
                        a();
                        com.iab.omid.library.prebidorg.internal.a aVar = (com.iab.omid.library.prebidorg.internal.a) this.d;
                        if (aVar != null) {
                            if (!aVar.e) {
                                aVar.a.getClass();
                                Date date = new Date();
                                Date date2 = aVar.b;
                                if (date2 == null || date.after(date2)) {
                                    aVar.b = date;
                                    if (aVar.c) {
                                        Iterator it2 = Collections.unmodifiableCollection(com.iab.omid.library.prebidorg.internal.c.c.b).iterator();
                                        if (it2.hasNext()) {
                                            throw android.support.v4.media.session.a.d(it2);
                                        }
                                    }
                                }
                            }
                            aVar.e = true;
                            return;
                        }
                        return;
                    }
                    return;
                }
                return;
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity activity) {
        boolean z;
        switch (this.a) {
            case 0:
                ActivityManager.RunningAppProcessInfo runningAppProcessInfo = new ActivityManager.RunningAppProcessInfo();
                ActivityManager.getMyMemoryState(runningAppProcessInfo);
                boolean z2 = runningAppProcessInfo.importance == 100 || u();
                if (this.c != z2) {
                    this.c = z2;
                    if (this.b) {
                        t(z2);
                        Rr rr = (Rr) this.d;
                        if (rr != null) {
                            rr.a(z2);
                            return;
                        }
                        return;
                    }
                    return;
                }
                return;
            case 1:
                ActivityManager.RunningAppProcessInfo runningAppProcessInfo2 = new ActivityManager.RunningAppProcessInfo();
                ActivityManager.getMyMemoryState(runningAppProcessInfo2);
                boolean z3 = runningAppProcessInfo2.importance == 100 || d();
                if (this.c != z3) {
                    this.c = z3;
                    if (this.b) {
                        b(z3);
                        com.iab.omid.library.amazon.internal.d dVar = (com.iab.omid.library.amazon.internal.d) this.d;
                        if (dVar != null) {
                            dVar.a(z3);
                            return;
                        }
                        return;
                    }
                    return;
                }
                return;
            default:
                ActivityManager.RunningAppProcessInfo runningAppProcessInfo3 = new ActivityManager.RunningAppProcessInfo();
                ActivityManager.getMyMemoryState(runningAppProcessInfo3);
                if (runningAppProcessInfo3.importance == 100) {
                    z = true;
                } else {
                    c();
                    z = false;
                }
                if (this.c != z) {
                    this.c = z;
                    if (this.b) {
                        a();
                        com.iab.omid.library.prebidorg.internal.a aVar = (com.iab.omid.library.prebidorg.internal.a) this.d;
                        if (aVar != null) {
                            if (!aVar.e && z) {
                                aVar.a.getClass();
                                Date date = new Date();
                                Date date2 = aVar.b;
                                if (date2 == null || date.after(date2)) {
                                    aVar.b = date;
                                    if (aVar.c) {
                                        Iterator it2 = Collections.unmodifiableCollection(com.iab.omid.library.prebidorg.internal.c.c.b).iterator();
                                        if (it2.hasNext()) {
                                            throw android.support.v4.media.session.a.d(it2);
                                        }
                                    }
                                }
                            }
                            aVar.e = z;
                            return;
                        }
                        return;
                    }
                    return;
                }
                return;
        }
    }

    public void t(boolean z) {
    }

    public boolean u() {
        return false;
    }
}
