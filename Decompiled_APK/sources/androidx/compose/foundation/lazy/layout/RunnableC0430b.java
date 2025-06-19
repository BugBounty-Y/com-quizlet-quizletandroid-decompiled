package androidx.compose.foundation.lazy.layout;

import android.view.Choreographer;
import android.view.View;
import androidx.compose.runtime.InterfaceC0834w0;

/* renamed from: androidx.compose.foundation.lazy.layout.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class RunnableC0430b implements q0, InterfaceC0834w0, Runnable, Choreographer.FrameCallback {
    public static long g;
    public final View a;
    public boolean c;
    public boolean e;
    public long f;
    public final androidx.compose.runtime.collection.b b = new androidx.compose.runtime.collection.b(new o0[16]);
    public final Choreographer d = Choreographer.getInstance();

    /* JADX WARN: Removed duplicated region for block: B:10:0x0035  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public RunnableC0430b(android.view.View r5) {
        /*
            r4 = this;
            r4.<init>()
            r4.a = r5
            androidx.compose.runtime.collection.b r0 = new androidx.compose.runtime.collection.b
            r1 = 16
            androidx.compose.foundation.lazy.layout.o0[] r1 = new androidx.compose.foundation.lazy.layout.o0[r1]
            r0.<init>(r1)
            r4.b = r0
            android.view.Choreographer r0 = android.view.Choreographer.getInstance()
            r4.d = r0
            long r0 = androidx.compose.foundation.lazy.layout.RunnableC0430b.g
            r2 = 0
            int r0 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r0 != 0) goto L3f
            android.view.Display r0 = r5.getDisplay()
            boolean r5 = r5.isInEditMode()
            if (r5 != 0) goto L35
            if (r0 == 0) goto L35
            float r5 = r0.getRefreshRate()
            r0 = 1106247680(0x41f00000, float:30.0)
            int r0 = (r5 > r0 ? 1 : (r5 == r0 ? 0 : -1))
            if (r0 < 0) goto L35
            goto L37
        L35:
            r5 = 1114636288(0x42700000, float:60.0)
        L37:
            r0 = 1000000000(0x3b9aca00, float:0.0047237873)
            float r0 = (float) r0
            float r0 = r0 / r5
            long r0 = (long) r0
            androidx.compose.foundation.lazy.layout.RunnableC0430b.g = r0
        L3f:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.layout.RunnableC0430b.<init>(android.view.View):void");
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        this.e = false;
        this.a.removeCallbacks(this);
        this.d.removeFrameCallback(this);
    }

    @Override // androidx.compose.foundation.lazy.layout.q0
    public final void c(o0 o0Var) {
        this.b.b(o0Var);
        if (this.c) {
            return;
        }
        this.c = true;
        this.a.post(this);
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() {
        this.e = true;
    }

    @Override // android.view.Choreographer.FrameCallback
    public final void doFrame(long j) {
        if (this.e) {
            this.f = j;
            this.a.post(this);
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        androidx.compose.runtime.collection.b bVar = this.b;
        if (bVar.l() || !this.c || !this.e || this.a.getWindowVisibility() != 0) {
            this.c = false;
            return;
        }
        C0429a c0429a = new C0429a(this.f + g);
        boolean z = false;
        while (bVar.m() && !z) {
            if (c0429a.a() <= 0 || ((o0) bVar.a[0]).b(c0429a)) {
                z = true;
            } else {
                bVar.o(0);
            }
        }
        if (z) {
            this.d.postFrameCallback(this);
        } else {
            this.c = false;
        }
    }
}
