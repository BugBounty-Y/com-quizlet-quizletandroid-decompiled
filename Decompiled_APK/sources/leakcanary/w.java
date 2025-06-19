package leakcanary;

import android.app.Application;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import java.util.LinkedHashSet;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public abstract class w {
    public static final /* synthetic */ w[] b = {new w() { // from class: leakcanary.p
        @Override // leakcanary.w
        public final void a(Application application) {
        }
    }, new t(), new w() { // from class: leakcanary.u
        @Override // leakcanary.w
        public final void a(Application application) {
        }
    }, new w() { // from class: leakcanary.j
        @Override // leakcanary.w
        public final void a(Application application) {
            if (Build.VERSION.SDK_INT >= 31) {
                return;
            }
            LinkedHashSet linkedHashSet = new LinkedHashSet();
            kotlin.u uVar = w.c;
            Looper looper = ((Handler) uVar.getValue()).getLooper();
            Intrinsics.c(looper, "backgroundHandler.looper");
            Thread thread = looper.getThread();
            if (thread == null) {
                throw new TypeCastException("null cannot be cast to non-null type android.os.HandlerThread");
            }
            linkedHashSet.add(Integer.valueOf(((HandlerThread) thread).getThreadId()));
            ((Handler) uVar.getValue()).postDelayed(new com.google.android.gms.common.api.internal.w(linkedHashSet, 20), 2000L);
        }
    }, new w() { // from class: leakcanary.b
        @Override // leakcanary.w
        public final void a(Application application) {
            if (Build.VERSION.SDK_INT >= 28) {
                return;
            }
            ((Handler) w.c.getValue()).postDelayed(new a(), 5000L);
        }
    }, new w() { // from class: leakcanary.e
        @Override // leakcanary.w
        public final void a(Application application) {
        }
    }, new w() { // from class: leakcanary.r
        @Override // leakcanary.w
        public final void a(Application application) {
            Intrinsics.b(Build.MANUFACTURER, "samsung");
        }
    }, new w() { // from class: leakcanary.d
        @Override // leakcanary.w
        public final void a(Application application) {
            Intrinsics.b(Build.MANUFACTURER, "LGE");
        }
    }, new w() { // from class: leakcanary.o
        @Override // leakcanary.w
        public final void a(Application application) {
            Intrinsics.b(Build.MANUFACTURER, "samsung");
        }
    }, new w() { // from class: leakcanary.c
        @Override // leakcanary.w
        public final void a(Application application) {
            Intrinsics.b(Build.MANUFACTURER, "samsung");
        }
    }, new w() { // from class: leakcanary.v
        /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, kotlin.k] */
        @Override // leakcanary.w
        public final void a(Application application) {
            if (Build.VERSION.SDK_INT != 28) {
                return;
            }
            ((curtains.internal.b) curtains.b.a.getValue()).a.add(new x(application));
            application.registerActivityLifecycleCallbacks(new g(application));
        }
    }, new w() { // from class: leakcanary.n
        @Override // leakcanary.w
        public final void a(Application application) {
        }
    }, new m(), new w() { // from class: leakcanary.s
        @Override // leakcanary.w
        public final void a(Application application) {
        }
    }, new w() { // from class: leakcanary.q
        @Override // leakcanary.w
        public final void a(Application application) {
            if (Build.VERSION.SDK_INT < 29) {
                return;
            }
            try {
                application.getSystemService("permission_controller");
            } catch (Exception unused) {
            }
        }
    }};
    public static final kotlin.u c = kotlin.l.b(f.a);
    public boolean a;

    /* JADX INFO: Fake field, exist only in values array */
    w EF2;

    public static w valueOf(String str) {
        return (w) Enum.valueOf(w.class, str);
    }

    public static w[] values() {
        return (w[]) b.clone();
    }

    public abstract void a(Application application);
}
