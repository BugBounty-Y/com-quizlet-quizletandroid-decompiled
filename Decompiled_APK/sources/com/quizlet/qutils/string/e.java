package com.quizlet.qutils.string;

import android.content.Context;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements g {
    public final String a;

    public e(String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        this.a = string;
    }

    @Override // com.quizlet.qutils.string.g
    public final String a(Context context) {
        return AbstractC3053s1.e(this, context);
    }

    @Override // com.quizlet.qutils.string.g
    public final String b(InterfaceC0806l interfaceC0806l) {
        return AbstractC3053s1.g(this, interfaceC0806l);
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence c(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return this.a;
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence d(InterfaceC0806l interfaceC0806l, int i) {
        return AbstractC3053s1.b(this, interfaceC0806l);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && Intrinsics.b(this.a, ((e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("RawStringData(string="), this.a, ")");
    }
}
