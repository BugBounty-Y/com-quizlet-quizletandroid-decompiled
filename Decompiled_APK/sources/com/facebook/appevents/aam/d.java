package com.facebook.appevents.aam;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewTreeObserver;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final class d implements ViewTreeObserver.OnGlobalFocusChangeListener {
    public static final HashMap e = new HashMap();
    public final WeakReference c;
    public final LinkedHashSet a = new LinkedHashSet();
    public final Handler b = new Handler(Looper.getMainLooper());
    public final AtomicBoolean d = new AtomicBoolean(false);

    public d(Activity activity) {
        this.c = new WeakReference(activity);
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:15:0x002f -> B:20:0x0032). Please report as a decompilation issue!!! */
    public final void a(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            androidx.credentials.playservices.controllers.c cVar = new androidx.credentials.playservices.controllers.c(18, view, this);
            if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                try {
                    if (Thread.currentThread() == Looper.getMainLooper().getThread()) {
                        cVar.run();
                    } else {
                        this.b.post(cVar);
                    }
                } catch (Throwable th) {
                    com.facebook.internal.instrument.crashshield.a.a(this, th);
                }
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:82:0x00e5 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:83:0x00da A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0104 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:86:0x005b A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(android.view.View r13) {
        /*
            Method dump skipped, instructions count: 277
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.aam.d.b(android.view.View):void");
    }

    @Override // android.view.ViewTreeObserver.OnGlobalFocusChangeListener
    public final void onGlobalFocusChanged(View view, View view2) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        if (view != null) {
            try {
                a(view);
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return;
            }
        }
        if (view2 != null) {
            a(view2);
        }
    }
}
