package androidx.activity;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I implements androidx.lifecycle.H, InterfaceC0031c {
    public final androidx.lifecycle.C a;
    public final D b;
    public J c;
    public final /* synthetic */ L d;

    public I(L l, androidx.lifecycle.C lifecycle, D onBackPressedCallback) {
        Intrinsics.checkNotNullParameter(lifecycle, "lifecycle");
        Intrinsics.checkNotNullParameter(onBackPressedCallback, "onBackPressedCallback");
        this.d = l;
        this.a = lifecycle;
        this.b = onBackPressedCallback;
        lifecycle.a(this);
    }

    @Override // androidx.activity.InterfaceC0031c
    public final void cancel() {
        this.a.b(this);
        D d = this.b;
        d.getClass();
        Intrinsics.checkNotNullParameter(this, "cancellable");
        d.b.remove(this);
        J j = this.c;
        if (j != null) {
            j.cancel();
        }
        this.c = null;
    }

    @Override // androidx.lifecycle.H
    public final void d(androidx.lifecycle.J source, androidx.lifecycle.A event) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(event, "event");
        if (event != androidx.lifecycle.A.ON_START) {
            if (event != androidx.lifecycle.A.ON_STOP) {
                if (event == androidx.lifecycle.A.ON_DESTROY) {
                    cancel();
                    return;
                }
                return;
            } else {
                J j = this.c;
                if (j != null) {
                    j.cancel();
                    return;
                }
                return;
            }
        }
        L l = this.d;
        D onBackPressedCallback = this.b;
        l.getClass();
        Intrinsics.checkNotNullParameter(onBackPressedCallback, "onBackPressedCallback");
        l.b.addLast(onBackPressedCallback);
        J cancellable = new J(l, onBackPressedCallback);
        Intrinsics.checkNotNullParameter(cancellable, "cancellable");
        onBackPressedCallback.b.add(cancellable);
        l.e();
        onBackPressedCallback.c = new K(0, l, L.class, "updateEnabledCallbacks", "updateEnabledCallbacks()V", 0, 1);
        this.c = cancellable;
    }
}
