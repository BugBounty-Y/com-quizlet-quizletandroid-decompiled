package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.login.LoginNavActivity;
import com.quizlet.quizletandroid.ui.globalnav.GlobalNavigationActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String c;
    public final String a;
    public final boolean b;

    static {
        String simpleName = r.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        c = simpleName;
    }

    public r(String code, boolean z) {
        Intrinsics.checkNotNullParameter(code, "code");
        this.a = code;
        this.b = z;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        boolean z = this.b;
        String magicLinkCode = this.a;
        if (!z) {
            String str = LoginNavActivity.i;
            return new Intent[]{com.google.android.gms.internal.mlkit_vision_document_scanner.B.b(context, magicLinkCode)};
        }
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(magicLinkCode, "magicLinkCode");
        String str2 = GlobalNavigationActivity.u;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(magicLinkCode, "magicLinkCode");
        Intent intent = new Intent(context, (Class<?>) GlobalNavigationActivity.class);
        intent.putExtra("GlobalNav.magicLinkCode", magicLinkCode);
        return new Intent[]{intent.addFlags(67108864)};
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final boolean b() {
        return false;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] c(Context context, h hVar) {
        return AbstractC3508o4.b(this, context, hVar);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return Intrinsics.b(this.a, rVar.a) && this.b == rVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return c;
    }

    public final String toString() {
        return "MagicLinkDeepLink(code=" + this.a + ", isLoggedIn=" + this.b + ")";
    }
}
