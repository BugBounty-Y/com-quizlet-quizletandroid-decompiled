package com.quizlet.quizletandroid.managers.deeplinks;

import android.app.TaskStackBuilder;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3309z0;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.features.folders.FolderActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String b;
    public final long a;

    static {
        String simpleName = p.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public p(long j) {
        this.a = j;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        String str = FolderActivity.j;
        Intent[] intents = TaskStackBuilder.create(context).addNextIntentWithParentStack(AbstractC3309z0.b(context, this.a)).getIntents();
        Intrinsics.checkNotNullExpressionValue(intents, "getIntents(...)");
        return intents;
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

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("FolderDeepLink("));
    }
}
