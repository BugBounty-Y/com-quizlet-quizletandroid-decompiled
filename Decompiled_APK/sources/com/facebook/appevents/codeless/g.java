package com.facebook.appevents.codeless;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import androidx.compose.ui.text.input.C;
import com.facebook.FacebookException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public static final c f = new c();
    public static g g;
    public final Handler a = new Handler(Looper.getMainLooper());
    public final Set b;
    public final LinkedHashSet c;
    public HashSet d;
    public final HashMap e;

    public g() {
        Set setNewSetFromMap = Collections.newSetFromMap(new WeakHashMap());
        Intrinsics.checkNotNullExpressionValue(setNewSetFromMap, "newSetFromMap(WeakHashMap())");
        this.b = setNewSetFromMap;
        this.c = new LinkedHashSet();
        this.d = new HashSet();
        this.e = new HashMap();
    }

    public final void a(Activity activity) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(activity, "activity");
            if (Thread.currentThread() != Looper.getMainLooper().getThread()) {
                throw new FacebookException("Can't add activity to CodelessMatcher on non-UI thread");
            }
            this.b.add(activity);
            this.d.clear();
            HashSet hashSet = (HashSet) this.e.get(Integer.valueOf(activity.hashCode()));
            if (hashSet != null) {
                this.d = hashSet;
            }
            if (com.facebook.internal.instrument.crashshield.a.b(this)) {
                return;
            }
            try {
                if (Thread.currentThread() == Looper.getMainLooper().getThread()) {
                    b();
                } else {
                    this.a.post(new C(this, 18));
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
        }
    }

    public final void b() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            for (Activity activity : this.b) {
                if (activity != null) {
                    View viewC = com.facebook.appevents.internal.d.c(activity);
                    String activityName = activity.getClass().getSimpleName();
                    Handler handler = this.a;
                    HashSet hashSet = this.d;
                    Intrinsics.checkNotNullExpressionValue(activityName, "activityName");
                    this.c.add(new f(viewC, handler, hashSet, activityName));
                }
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final void c(Activity activity) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(activity, "activity");
            if (Thread.currentThread() != Looper.getMainLooper().getThread()) {
                throw new FacebookException("Can't remove activity from CodelessMatcher on non-UI thread");
            }
            this.b.remove(activity);
            this.c.clear();
            HashMap map = this.e;
            Integer numValueOf = Integer.valueOf(activity.hashCode());
            Object objClone = this.d.clone();
            Intrinsics.e(objClone, "null cannot be cast to non-null type java.util.HashSet<kotlin.String>{ kotlin.collections.TypeAliasesKt.HashSet<kotlin.String> }");
            map.put(numValueOf, (HashSet) objClone);
            this.d.clear();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
