package androidx.activity;

import android.window.BackEvent;
import android.window.OnBackAnimationCallback;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class H implements OnBackAnimationCallback {
    public final /* synthetic */ E a;
    public final /* synthetic */ E b;
    public final /* synthetic */ F c;
    public final /* synthetic */ F d;

    public H(E e, E e2, F f, F f2) {
        this.a = e;
        this.b = e2;
        this.c = f;
        this.d = f2;
    }

    public final void onBackCancelled() {
        this.d.invoke();
    }

    public final void onBackInvoked() {
        this.c.invoke();
    }

    public final void onBackProgressed(BackEvent backEvent) {
        Intrinsics.checkNotNullParameter(backEvent, "backEvent");
        this.b.invoke(new C0030b(backEvent));
    }

    public final void onBackStarted(BackEvent backEvent) {
        Intrinsics.checkNotNullParameter(backEvent, "backEvent");
        this.a.invoke(new C0030b(backEvent));
    }
}
