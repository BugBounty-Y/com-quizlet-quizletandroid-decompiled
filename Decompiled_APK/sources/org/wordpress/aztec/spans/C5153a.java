package org.wordpress.aztec.spans;

import android.R;
import android.content.Context;
import android.graphics.drawable.Drawable;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* renamed from: org.wordpress.aztec.spans.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5153a extends AbstractC5167o implements G, M {
    public int g;
    public final String h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5153a(Context context, Drawable drawable, int i, C5146b attributes) {
        super(drawable, attributes);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.g = i;
        this.h = "audio";
        c(com.facebook.appevents.g.f(context, R.drawable.ic_lock_silent_mode_off));
    }

    @Override // org.wordpress.aztec.spans.K
    public final int a() {
        return this.g;
    }

    @Override // org.wordpress.aztec.spans.K
    public final void t(int i) {
        this.g = i;
    }

    @Override // org.wordpress.aztec.spans.AbstractC5167o, org.wordpress.aztec.spans.M
    public final String u() {
        return this.h;
    }
}
