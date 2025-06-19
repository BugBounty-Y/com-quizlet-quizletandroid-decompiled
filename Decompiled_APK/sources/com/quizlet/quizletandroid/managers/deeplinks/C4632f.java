package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import androidx.core.app.W;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.managers.deeplinks.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4632f implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String a;

    static {
        String simpleName = C4632f.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        a = simpleName;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        W w = new W(context);
        w.a(D4.a(context, GlobalNavReroute.CreateSet.a));
        Intent[] intentArrC = w.c();
        Intrinsics.checkNotNullExpressionValue(intentArrC, "getIntents(...)");
        return intentArrC;
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
        return a;
    }
}
