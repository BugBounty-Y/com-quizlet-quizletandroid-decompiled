package com.facebook.appevents.suggestedevents;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.view.ViewTreeObserver;
import androidx.compose.ui.text.input.C;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final class e implements ViewTreeObserver.OnGlobalLayoutListener {
    public static final HashMap d = new HashMap();
    public final WeakReference a;
    public final Handler b = new Handler(Looper.getMainLooper());
    public final AtomicBoolean c = new AtomicBoolean(false);

    public e(Activity activity) {
        this.a = new WeakReference(activity);
    }

    public final void a() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            C c = new C(this, 19);
            if (Thread.currentThread() == Looper.getMainLooper().getThread()) {
                c.run();
            } else {
                this.b.post(c);
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            a();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
