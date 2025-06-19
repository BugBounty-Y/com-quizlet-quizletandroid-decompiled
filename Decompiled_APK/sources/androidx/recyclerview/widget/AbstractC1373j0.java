package androidx.recyclerview.widget;

import androidx.compose.material3.C0676l1;
import java.util.ArrayList;

/* renamed from: androidx.recyclerview.widget.j0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1373j0 {
    public C1357b0 a;
    public ArrayList b;
    public long c;
    public long d;
    public long e;
    public long f;

    public static void b(F0 f0) {
        int i = f0.mFlags;
        if (!f0.isInvalid() && (i & 4) == 0) {
            f0.getOldPosition();
            f0.getAbsoluteAdapterPosition();
        }
    }

    public abstract boolean a(F0 f0, F0 f02, C0676l1 c0676l1, C0676l1 c0676l12);

    /* JADX WARN: Removed duplicated region for block: B:32:0x006c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(androidx.recyclerview.widget.F0 r10) {
        /*
            r9 = this;
            androidx.recyclerview.widget.b0 r0 = r9.a
            if (r0 == 0) goto La0
            r1 = 1
            r10.setIsRecyclable(r1)
            androidx.recyclerview.widget.F0 r2 = r10.mShadowedHolder
            r3 = 0
            if (r2 == 0) goto L13
            androidx.recyclerview.widget.F0 r2 = r10.mShadowingHolder
            if (r2 != 0) goto L13
            r10.mShadowedHolder = r3
        L13:
            r10.mShadowingHolder = r3
            boolean r2 = r10.shouldBeKeptAsChild()
            if (r2 != 0) goto La0
            android.view.View r2 = r10.itemView
            androidx.recyclerview.widget.RecyclerView r0 = r0.a
            r0.o0()
            androidx.camera.camera2.internal.concurrent.a r3 = r0.f
            java.lang.Object r4 = r3.e
            androidx.compose.foundation.gestures.l1 r4 = (androidx.compose.foundation.gestures.l1) r4
            java.lang.Object r5 = r3.d
            androidx.recyclerview.widget.b0 r5 = (androidx.recyclerview.widget.C1357b0) r5
            int r6 = r3.b
            r7 = 0
            if (r6 != r1) goto L41
            java.lang.Object r1 = r3.f
            android.view.View r1 = (android.view.View) r1
            if (r1 != r2) goto L39
        L37:
            r1 = r7
            goto L6a
        L39:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "Cannot call removeViewIfHidden within removeView(At) for a different view"
            r10.<init>(r0)
            throw r10
        L41:
            r8 = 2
            if (r6 == r8) goto L98
            r3.b = r8     // Catch: java.lang.Throwable -> L55
            androidx.recyclerview.widget.RecyclerView r6 = r5.a     // Catch: java.lang.Throwable -> L55
            int r6 = r6.indexOfChild(r2)     // Catch: java.lang.Throwable -> L55
            r8 = -1
            if (r6 != r8) goto L57
            r3.S(r2)     // Catch: java.lang.Throwable -> L55
        L52:
            r3.b = r7
            goto L6a
        L55:
            r10 = move-exception
            goto L95
        L57:
            boolean r8 = r4.v(r6)     // Catch: java.lang.Throwable -> L55
            if (r8 == 0) goto L67
            r4.F(r6)     // Catch: java.lang.Throwable -> L55
            r3.S(r2)     // Catch: java.lang.Throwable -> L55
            r5.h(r6)     // Catch: java.lang.Throwable -> L55
            goto L52
        L67:
            r3.b = r7
            goto L37
        L6a:
            if (r1 == 0) goto L82
            androidx.recyclerview.widget.F0 r3 = androidx.recyclerview.widget.RecyclerView.P(r2)
            androidx.recyclerview.widget.v0 r4 = r0.c
            r4.l(r3)
            r4.i(r3)
            boolean r3 = androidx.recyclerview.widget.RecyclerView.N1
            if (r3 == 0) goto L82
            java.util.Objects.toString(r2)
            r0.toString()
        L82:
            r2 = r1 ^ 1
            r0.q0(r2)
            if (r1 != 0) goto La0
            boolean r1 = r10.isTmpDetached()
            if (r1 == 0) goto La0
            android.view.View r10 = r10.itemView
            r0.removeDetachedView(r10, r7)
            return
        L95:
            r3.b = r7
            throw r10
        L98:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "Cannot call removeViewIfHidden within removeViewIfHidden"
            r10.<init>(r0)
            throw r10
        La0:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.AbstractC1373j0.c(androidx.recyclerview.widget.F0):void");
    }

    public abstract void d(F0 f0);

    public abstract void e();

    public abstract boolean f();
}
