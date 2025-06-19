package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.app.Application;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.IntentFilter;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.Window;
import com.facebook.internal.C1549d;
import java.lang.ref.WeakReference;

/* renamed from: com.google.android.gms.internal.ads.d5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ViewOnAttachStateChangeListenerC1952d5 implements View.OnAttachStateChangeListener, ViewTreeObserver.OnGlobalLayoutListener, ViewTreeObserver.OnScrollChangedListener, Application.ActivityLifecycleCallbacks {
    public static final Handler m = new Handler(Looper.getMainLooper());
    public final Context a;
    public final Application b;
    public final PowerManager c;
    public final KeyguardManager d;
    public C1549d e;
    public final V4 f;
    public WeakReference g;
    public WeakReference h;
    public final U4 i;
    public byte j = -1;
    public int k = -1;
    public long l = -3;

    public ViewOnAttachStateChangeListenerC1952d5(Context context, V4 v4) {
        Context applicationContext = context.getApplicationContext();
        this.a = applicationContext;
        this.f = v4;
        this.c = (PowerManager) applicationContext.getSystemService("power");
        this.d = (KeyguardManager) applicationContext.getSystemService("keyguard");
        if (applicationContext instanceof Application) {
            Application application = (Application) applicationContext;
            this.b = application;
            this.i = new U4(application, this);
        }
        a(null);
    }

    public final void a(View view) {
        long j;
        WeakReference weakReference = this.h;
        View view2 = weakReference != null ? (View) weakReference.get() : null;
        if (view2 != null) {
            view2.removeOnAttachStateChangeListener(this);
            e(view2);
        }
        this.h = new WeakReference(view);
        if (view != null) {
            if (view.getWindowToken() != null || view.getWindowVisibility() != 8) {
                d(view);
            }
            view.addOnAttachStateChangeListener(this);
            j = -2;
        } else {
            j = -3;
        }
        this.l = j;
    }

    public final void b(int i, Activity activity) {
        Window window;
        if (this.h == null || (window = activity.getWindow()) == null) {
            return;
        }
        View viewPeekDecorView = window.peekDecorView();
        WeakReference weakReference = this.h;
        View view = weakReference != null ? (View) weakReference.get() : null;
        if (view == null || viewPeekDecorView == null || view.getRootView() != viewPeekDecorView.getRootView()) {
            return;
        }
        this.k = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:53:0x0086  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c() {
        /*
            r10 = this;
            r0 = 1
            java.lang.ref.WeakReference r1 = r10.h
            if (r1 != 0) goto L7
            goto Lc2
        L7:
            r2 = 0
            if (r1 == 0) goto L11
            java.lang.Object r1 = r1.get()
            android.view.View r1 = (android.view.View) r1
            goto L12
        L11:
            r1 = r2
        L12:
            r3 = -1
            r4 = -3
            if (r1 != 0) goto L1c
            r10.l = r4
            r10.j = r3
            return
        L1c:
            int r6 = r1.getVisibility()
            r7 = 0
            if (r6 == 0) goto L25
            r6 = r0
            goto L26
        L25:
            r6 = r7
        L26:
            boolean r8 = r1.isShown()
            if (r8 != 0) goto L2e
            r6 = r6 | 2
        L2e:
            android.os.PowerManager r8 = r10.c
            if (r8 == 0) goto L3a
            boolean r8 = r8.isScreenOn()
            if (r8 != 0) goto L3a
            r6 = r6 | 4
        L3a:
            com.google.android.gms.internal.ads.V4 r8 = r10.f
            boolean r8 = r8.a
            if (r8 != 0) goto L88
            android.app.KeyguardManager r8 = r10.d
            if (r8 == 0) goto L86
            boolean r8 = r8.inKeyguardRestrictedInputMode()
            if (r8 == 0) goto L86
            char[] r8 = com.google.android.gms.internal.ads.AbstractC1865b5.a
            android.view.View r8 = r1.getRootView()
            if (r8 != 0) goto L53
            r8 = r1
        L53:
            android.content.Context r8 = r8.getContext()
        L57:
            boolean r9 = r8 instanceof android.content.ContextWrapper
            if (r9 == 0) goto L6e
            r9 = 10
            if (r7 >= r9) goto L6e
            boolean r9 = r8 instanceof android.app.Activity
            if (r9 == 0) goto L66
            android.app.Activity r8 = (android.app.Activity) r8
            goto L6f
        L66:
            android.content.ContextWrapper r8 = (android.content.ContextWrapper) r8
            android.content.Context r8 = r8.getBaseContext()
            int r7 = r7 + r0
            goto L57
        L6e:
            r8 = r2
        L6f:
            if (r8 != 0) goto L72
            goto L86
        L72:
            android.view.Window r0 = r8.getWindow()
            if (r0 != 0) goto L79
            goto L7d
        L79:
            android.view.WindowManager$LayoutParams r2 = r0.getAttributes()
        L7d:
            if (r2 == 0) goto L86
            int r0 = r2.flags
            r2 = 524288(0x80000, float:7.34684E-40)
            r0 = r0 & r2
            if (r0 != 0) goto L88
        L86:
            r6 = r6 | 8
        L88:
            android.graphics.Rect r0 = new android.graphics.Rect
            r0.<init>()
            boolean r0 = r1.getGlobalVisibleRect(r0)
            if (r0 != 0) goto L95
            r6 = r6 | 16
        L95:
            android.graphics.Rect r0 = new android.graphics.Rect
            r0.<init>()
            boolean r0 = r1.getLocalVisibleRect(r0)
            if (r0 != 0) goto La2
            r6 = r6 | 32
        La2:
            int r0 = r1.getWindowVisibility()
            int r1 = r10.k
            if (r1 == r3) goto Lab
            r0 = r1
        Lab:
            if (r0 == 0) goto Laf
            r6 = r6 | 64
        Laf:
            byte r0 = r10.j
            if (r0 == r6) goto Lc2
            byte r0 = (byte) r6
            r10.j = r0
            if (r6 != 0) goto Lbd
            long r0 = android.os.SystemClock.elapsedRealtime()
            goto Lc0
        Lbd:
            long r0 = (long) r6
            long r0 = r4 - r0
        Lc0:
            r10.l = r0
        Lc2:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.ViewOnAttachStateChangeListenerC1952d5.c():void");
    }

    public final void d(View view) {
        ViewTreeObserver viewTreeObserver = view.getViewTreeObserver();
        if (viewTreeObserver.isAlive()) {
            this.g = new WeakReference(viewTreeObserver);
            viewTreeObserver.addOnScrollChangedListener(this);
            viewTreeObserver.addOnGlobalLayoutListener(this);
        }
        if (this.e == null) {
            IntentFilter intentFilter = new IntentFilter();
            intentFilter.addAction("android.intent.action.SCREEN_ON");
            intentFilter.addAction("android.intent.action.SCREEN_OFF");
            intentFilter.addAction("android.intent.action.USER_PRESENT");
            C1549d c1549d = new C1549d(this, 7);
            this.e = c1549d;
            this.a.registerReceiver(c1549d, intentFilter);
        }
        Application application = this.b;
        if (application != null) {
            try {
                application.registerActivityLifecycleCallbacks(this.i);
            } catch (Exception unused) {
            }
        }
    }

    public final void e(View view) {
        try {
            WeakReference weakReference = this.g;
            if (weakReference != null) {
                ViewTreeObserver viewTreeObserver = (ViewTreeObserver) weakReference.get();
                if (viewTreeObserver != null && viewTreeObserver.isAlive()) {
                    viewTreeObserver.removeOnScrollChangedListener(this);
                    viewTreeObserver.removeGlobalOnLayoutListener(this);
                }
                this.g = null;
            }
        } catch (Exception unused) {
        }
        try {
            ViewTreeObserver viewTreeObserver2 = view.getViewTreeObserver();
            if (viewTreeObserver2.isAlive()) {
                viewTreeObserver2.removeOnScrollChangedListener(this);
                viewTreeObserver2.removeGlobalOnLayoutListener(this);
            }
        } catch (Exception unused2) {
        }
        C1549d c1549d = this.e;
        if (c1549d != null) {
            try {
                this.a.unregisterReceiver(c1549d);
            } catch (Exception unused3) {
            }
            this.e = null;
        }
        Application application = this.b;
        if (application != null) {
            try {
                application.unregisterActivityLifecycleCallbacks(this.i);
            } catch (Exception unused4) {
            }
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityCreated(Activity activity, Bundle bundle) {
        b(0, activity);
        c();
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityDestroyed(Activity activity) {
        c();
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityPaused(Activity activity) {
        b(4, activity);
        c();
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityResumed(Activity activity) {
        b(0, activity);
        c();
        m.post(new RunnableC1989e(this, 4));
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
        c();
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStarted(Activity activity) {
        b(0, activity);
        c();
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public final void onActivityStopped(Activity activity) {
        c();
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        c();
    }

    @Override // android.view.ViewTreeObserver.OnScrollChangedListener
    public final void onScrollChanged() {
        c();
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewAttachedToWindow(View view) {
        this.k = -1;
        d(view);
        c();
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewDetachedFromWindow(View view) {
        this.k = -1;
        c();
        m.post(new RunnableC1989e(this, 4));
        e(view);
    }
}
