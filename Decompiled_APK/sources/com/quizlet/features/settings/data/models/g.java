package com.quizlet.features.settings.data.models;

import android.content.Context;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.quizlet.api.model.ServerProvidedError;
import com.quizlet.api.util.ApiErrorResolver;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements com.quizlet.qutils.string.g {
    public final ServerProvidedError a;

    public g(ServerProvidedError error) {
        Intrinsics.checkNotNullParameter(error, "error");
        this.a = error;
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
        String strA = ApiErrorResolver.a(context, this.a);
        if (strA != null) {
            return strA;
        }
        String string = context.getString(R.string.client_error_net_exception);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        return string;
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence d(InterfaceC0806l interfaceC0806l, int i) {
        return AbstractC3053s1.b(this, interfaceC0806l);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Intrinsics.b(this.a, ((g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SettingsApiErrorStringResData(error=" + this.a + ")";
    }
}
