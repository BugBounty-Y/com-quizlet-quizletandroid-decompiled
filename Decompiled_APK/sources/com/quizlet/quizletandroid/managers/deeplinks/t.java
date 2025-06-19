package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import androidx.core.app.W;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.data.model.m2;
import com.quizlet.features.notes.detail.MagicNotesDetailActivity;
import com.quizlet.features.notes.upload.UploadNotesActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String b;
    public final String a;

    static {
        String simpleName = t.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public t(String str) {
        this.a = str;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Context context2;
        Intent intentJ;
        Intrinsics.checkNotNullParameter(context, "context");
        String str = this.a;
        if (str == null) {
            int i = UploadNotesActivity.i;
            context2 = context;
            intentJ = com.google.android.gms.internal.mlkit_common.u.i(context2, m2.a, null, null, null, 28);
        } else {
            context2 = context;
            int i2 = MagicNotesDetailActivity.i;
            intentJ = assistantMode.utils.studiableMetadata.b.J(context2, str, false, null);
        }
        W w = new W(context2);
        w.a(intentJ);
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

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof t) && Intrinsics.b(this.a, ((t) obj).a);
    }

    public final int hashCode() {
        String str = this.a;
        if (str == null) {
            return 0;
        }
        return str.hashCode();
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return b;
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("NotesDeepLink(uuid="), this.a, ")");
    }
}
