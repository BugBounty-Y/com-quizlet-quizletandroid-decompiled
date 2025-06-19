package androidx.lifecycle;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class K {
    public B a;
    public H b;

    public final void a(J j, A event) {
        Intrinsics.checkNotNullParameter(event, "event");
        B bA = event.a();
        B state1 = this.a;
        Intrinsics.checkNotNullParameter(state1, "state1");
        if (bA.compareTo(state1) < 0) {
            state1 = bA;
        }
        this.a = state1;
        this.b.d(j, event);
        this.a = bA;
    }
}
