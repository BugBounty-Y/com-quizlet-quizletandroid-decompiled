package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.login.LoginNavActivity;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String b;
    public final B a;

    static {
        String simpleName = C.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public C(B error) {
        Intrinsics.checkNotNullParameter(error, "error");
        this.a = error;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        int iOrdinal = this.a.ordinal();
        if (iOrdinal == 0) {
            return new Intent[]{D4.a(context, null)};
        }
        if (iOrdinal != 1 && iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        String str = LoginNavActivity.i;
        return new Intent[]{com.google.android.gms.internal.mlkit_vision_document_scanner.B.a(context)};
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final boolean b() {
        return false;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] c(Context context, h hVar) {
        return AbstractC3508o4.b(this, context, hVar);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return b;
    }
}
