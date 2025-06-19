package com.quizlet.features.paywall.state;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements c {
    public final String a;
    public final String b;
    public final String c;
    public final String d;

    public a(String message, String header, String primaryButton, String secondaryButton) {
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(header, "header");
        Intrinsics.checkNotNullParameter(primaryButton, "primaryButton");
        Intrinsics.checkNotNullParameter(secondaryButton, "secondaryButton");
        this.a = message;
        this.b = header;
        this.c = primaryButton;
        this.d = secondaryButton;
    }

    @Override // com.quizlet.features.paywall.state.c
    public final String a() {
        return this.a;
    }

    @Override // com.quizlet.features.paywall.state.c
    public final String b() {
        return this.d;
    }

    @Override // com.quizlet.features.paywall.state.c
    public final String c() {
        return this.c;
    }

    @Override // com.quizlet.features.paywall.state.c
    public final String d() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Loaded(message=");
        sb.append(this.a);
        sb.append(", header=");
        sb.append(this.b);
        sb.append(", primaryButton=");
        sb.append(this.c);
        sb.append(", secondaryButton=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
