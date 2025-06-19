package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import androidx.core.app.W;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.google.android.gms.internal.mlkit_vision_common.M3;
import com.quizlet.data.model.m2;
import com.quizlet.features.universaluploadflow.UniversalUploadFlowActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class v implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String a;

    static {
        String simpleName = v.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        a = simpleName;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        int i = UniversalUploadFlowActivity.h;
        Intent intentA = M3.a(context, m2.c);
        W w = new W(context);
        w.a(intentA);
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
