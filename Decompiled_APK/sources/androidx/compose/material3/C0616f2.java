package androidx.compose.material3;

import android.window.BackEvent;
import android.window.OnBackAnimationCallback;
import androidx.compose.animation.core.C0238e;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.material3.f2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0616f2 implements OnBackAnimationCallback {
    public final /* synthetic */ kotlinx.coroutines.C a;
    public final /* synthetic */ C0238e b;
    public final /* synthetic */ Function0 c;

    public C0616f2(Function0 function0, C0238e c0238e, kotlinx.coroutines.C c) {
        this.a = c;
        this.b = c0238e;
        this.c = function0;
    }

    public final void onBackCancelled() {
        kotlinx.coroutines.E.A(this.a, null, null, new C0598c2(this.b, null), 3);
    }

    public final void onBackInvoked() {
        this.c.invoke();
    }

    public final void onBackProgressed(BackEvent backEvent) {
        kotlinx.coroutines.E.A(this.a, null, null, new C0604d2(this.b, backEvent, null), 3);
    }

    public final void onBackStarted(BackEvent backEvent) {
        kotlinx.coroutines.E.A(this.a, null, null, new C0610e2(this.b, backEvent, null), 3);
    }
}
