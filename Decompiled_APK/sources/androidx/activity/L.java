package androidx.activity;

import android.os.Build;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;
import java.util.Iterator;
import java.util.ListIterator;
import kotlin.collections.C4927s;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L {
    public final Runnable a;
    public final C4927s b = new C4927s();
    public D c;
    public final OnBackInvokedCallback d;
    public OnBackInvokedDispatcher e;
    public boolean f;
    public boolean g;

    public L(Runnable runnable) {
        OnBackInvokedCallback g;
        this.a = runnable;
        int i = Build.VERSION.SDK_INT;
        if (i >= 33) {
            if (i >= 34) {
                E onBackStarted = new E(this, 0);
                E onBackProgressed = new E(this, 1);
                F onBackInvoked = new F(this, 0);
                F onBackCancelled = new F(this, 1);
                Intrinsics.checkNotNullParameter(onBackStarted, "onBackStarted");
                Intrinsics.checkNotNullParameter(onBackProgressed, "onBackProgressed");
                Intrinsics.checkNotNullParameter(onBackInvoked, "onBackInvoked");
                Intrinsics.checkNotNullParameter(onBackCancelled, "onBackCancelled");
                g = new H(onBackStarted, onBackProgressed, onBackInvoked, onBackCancelled);
            } else {
                F onBackInvoked2 = new F(this, 2);
                Intrinsics.checkNotNullParameter(onBackInvoked2, "onBackInvoked");
                g = new G(onBackInvoked2, 0);
            }
            this.d = g;
        }
    }

    public final void a(androidx.lifecycle.J owner, D onBackPressedCallback) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(onBackPressedCallback, "onBackPressedCallback");
        androidx.lifecycle.C lifecycle = owner.getLifecycle();
        if (((androidx.lifecycle.L) lifecycle).d == androidx.lifecycle.B.a) {
            return;
        }
        I cancellable = new I(this, lifecycle, onBackPressedCallback);
        onBackPressedCallback.getClass();
        Intrinsics.checkNotNullParameter(cancellable, "cancellable");
        onBackPressedCallback.b.add(cancellable);
        e();
        onBackPressedCallback.c = new K(0, this, L.class, "updateEnabledCallbacks", "updateEnabledCallbacks()V", 0, 0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r2v4, types: [java.lang.Object] */
    public final void b() {
        D dPrevious;
        D d = this.c;
        if (d == null) {
            C4927s c4927s = this.b;
            ListIterator listIterator = c4927s.listIterator(c4927s.size());
            while (true) {
                if (!listIterator.hasPrevious()) {
                    dPrevious = 0;
                    break;
                } else {
                    dPrevious = listIterator.previous();
                    if (((D) dPrevious).a) {
                        break;
                    }
                }
            }
            d = dPrevious;
        }
        this.c = null;
        if (d != null) {
            d.a();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r2v4, types: [java.lang.Object] */
    public final void c() {
        D dPrevious;
        D d = this.c;
        if (d == null) {
            C4927s c4927s = this.b;
            ListIterator listIterator = c4927s.listIterator(c4927s.a());
            while (true) {
                if (!listIterator.hasPrevious()) {
                    dPrevious = 0;
                    break;
                } else {
                    dPrevious = listIterator.previous();
                    if (((D) dPrevious).a) {
                        break;
                    }
                }
            }
            d = dPrevious;
        }
        this.c = null;
        if (d != null) {
            d.b();
        } else {
            this.a.run();
        }
    }

    public final void d(boolean z) {
        OnBackInvokedDispatcher onBackInvokedDispatcher = this.e;
        OnBackInvokedCallback onBackInvokedCallback = this.d;
        if (onBackInvokedDispatcher == null || onBackInvokedCallback == null) {
            return;
        }
        if (z && !this.f) {
            AbstractC0037i.h(onBackInvokedDispatcher, onBackInvokedCallback);
            this.f = true;
        } else {
            if (z || !this.f) {
                return;
            }
            AbstractC0037i.i(onBackInvokedDispatcher, onBackInvokedCallback);
            this.f = false;
        }
    }

    public final void e() {
        boolean z = this.g;
        boolean z2 = false;
        C4927s c4927s = this.b;
        if (c4927s == null || !c4927s.isEmpty()) {
            Iterator<E> it2 = c4927s.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                } else if (((D) it2.next()).a) {
                    z2 = true;
                    break;
                }
            }
        }
        this.g = z2;
        if (z2 == z || Build.VERSION.SDK_INT < 33) {
            return;
        }
        d(z2);
    }
}
