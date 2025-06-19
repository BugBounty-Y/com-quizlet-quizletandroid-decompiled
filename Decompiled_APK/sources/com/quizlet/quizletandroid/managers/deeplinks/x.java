package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.N5;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import com.quizlet.quizletandroid.ui.search.SearchActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String c;
    public final boolean a;
    public final String b;

    static {
        String simpleName = x.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        c = simpleName;
    }

    public x(boolean z, String str) {
        this.a = z;
        this.b = str;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intent intentD;
        Intrinsics.checkNotNullParameter(context, "context");
        boolean z = this.a;
        String str = this.b;
        if (z) {
            intentD = D4.a(context, new GlobalNavReroute.Search(str)).addFlags(67108864);
        } else {
            String str2 = SearchActivity.q;
            intentD = N5.d(context, str);
        }
        Intrinsics.d(intentD);
        return new Intent[]{intentD};
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
        return c;
    }
}
