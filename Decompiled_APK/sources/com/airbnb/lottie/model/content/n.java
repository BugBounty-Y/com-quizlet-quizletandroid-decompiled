package com.airbnb.lottie.model.content;

import com.airbnb.lottie.animation.content.r;
import com.airbnb.lottie.u;

/* loaded from: classes.dex */
public final class n implements b {
    public final String a;
    public final int b;
    public final com.airbnb.lottie.model.animatable.a c;
    public final boolean d;

    public n(String str, int i, com.airbnb.lottie.model.animatable.a aVar, boolean z) {
        this.a = str;
        this.b = i;
        this.c = aVar;
        this.d = z;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        return new r(uVar, bVar, this);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ShapePath{name=");
        sb.append(this.a);
        sb.append(", index=");
        return android.support.v4.media.session.a.q(sb, this.b, '}');
    }
}
