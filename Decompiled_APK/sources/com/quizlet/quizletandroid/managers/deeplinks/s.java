package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.quizletandroid.ui.RootActivity;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s extends AbstractC3705q4 {
    public static final String b;
    public final boolean a;

    static {
        String simpleName = s.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public s(boolean z) {
        this.a = z;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return new Intent[]{this.a ? D4.a(context, GlobalNavReroute.ViewAllExplanations.a) : new Intent(context, (Class<?>) RootActivity.class)};
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof s) && this.a == ((s) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return b;
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("MyExplanationsDeepLink(isLoggedIn="), this.a);
    }
}
