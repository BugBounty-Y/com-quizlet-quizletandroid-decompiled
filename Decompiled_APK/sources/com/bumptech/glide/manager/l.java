package com.bumptech.glide.manager;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import androidx.collection.C0208f;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import com.bumptech.glide.Glide;
import com.bumptech.glide.load.resource.bitmap.u;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class l implements Handler.Callback {
    public static final com.google.mlkit.common.internal.model.a e = new com.google.mlkit.common.internal.model.a(7);
    public volatile com.bumptech.glide.m a;
    public final f c;
    public final C0208f b = new C0208f(0);
    public final androidx.work.impl.model.e d = new androidx.work.impl.model.e(e);

    public l() {
        this.c = (u.f && u.e) ? new e() : new com.google.android.material.shape.e(7);
    }

    public static Activity a(Context context) {
        if (context instanceof Activity) {
            return (Activity) context;
        }
        if (context instanceof ContextWrapper) {
            return a(((ContextWrapper) context).getBaseContext());
        }
        return null;
    }

    public static void b(List list, C0208f c0208f) {
        if (list == null) {
            return;
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            Fragment fragment = (Fragment) it2.next();
            if (fragment != null && fragment.getView() != null) {
                c0208f.put(fragment.getView(), fragment);
                b(fragment.getChildFragmentManager().c.f(), c0208f);
            }
        }
    }

    public final com.bumptech.glide.m c(Context context) {
        int i = 7;
        if (context == null) {
            throw new IllegalArgumentException("You cannot start a load on a null Context");
        }
        char[] cArr = com.bumptech.glide.util.m.a;
        if (Looper.myLooper() == Looper.getMainLooper() && !(context instanceof Application)) {
            if (context instanceof I) {
                return d((I) context);
            }
            if (context instanceof ContextWrapper) {
                ContextWrapper contextWrapper = (ContextWrapper) context;
                if (contextWrapper.getBaseContext().getApplicationContext() != null) {
                    return c(contextWrapper.getBaseContext());
                }
            }
        }
        if (this.a == null) {
            synchronized (this) {
                try {
                    if (this.a == null) {
                        this.a = new com.bumptech.glide.m(Glide.a(context.getApplicationContext()), new assistantMode.utils.studiableMetadata.b(i), new com.google.firebase.heartbeatinfo.e(7), context.getApplicationContext());
                    }
                } finally {
                }
            }
        }
        return this.a;
    }

    public final com.bumptech.glide.m d(I i) {
        char[] cArr = com.bumptech.glide.util.m.a;
        if (!(Looper.myLooper() == Looper.getMainLooper())) {
            return c(i.getApplicationContext());
        }
        if (i.isDestroyed()) {
            throw new IllegalArgumentException("You cannot start a load for a destroyed activity");
        }
        this.c.c(i);
        Activity activityA = a(i);
        return this.d.r(i, Glide.a(i.getApplicationContext()), i.getLifecycle(), i.getSupportFragmentManager(), activityA == null || !activityA.isFinishing());
    }

    @Override // android.os.Handler.Callback
    public final boolean handleMessage(Message message) {
        return false;
    }
}
