package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.quizletandroid.ui.RootActivity;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String b;
    public final boolean a;

    static {
        String simpleName = m.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public m(boolean z) {
        this.a = z;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (!this.a) {
            return new Intent[]{new Intent(context, (Class<?>) RootActivity.class)};
        }
        Intent intentAddFlags = D4.a(context, GlobalNavReroute.EdgyDataCollection.a).addFlags(67108864);
        Intrinsics.checkNotNullExpressionValue(intentAddFlags, "addFlags(...)");
        return new Intent[]{intentAddFlags};
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
