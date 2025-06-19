package androidx.activity;

import android.window.BackEvent;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.activity.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0030b {
    public final float a;
    public final float b;
    public final float c;
    public final int d;

    public C0030b(BackEvent backEvent) {
        Intrinsics.checkNotNullParameter(backEvent, "backEvent");
        float fN = AbstractC0029a.n(backEvent);
        float fO = AbstractC0029a.o(backEvent);
        float fK = AbstractC0029a.k(backEvent);
        int iM = AbstractC0029a.m(backEvent);
        this.a = fN;
        this.b = fO;
        this.c = fK;
        this.d = iM;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BackEventCompat{touchX=");
        sb.append(this.a);
        sb.append(", touchY=");
        sb.append(this.b);
        sb.append(", progress=");
        sb.append(this.c);
        sb.append(", swipeEdge=");
        return android.support.v4.media.session.a.q(sb, this.d, '}');
    }
}
