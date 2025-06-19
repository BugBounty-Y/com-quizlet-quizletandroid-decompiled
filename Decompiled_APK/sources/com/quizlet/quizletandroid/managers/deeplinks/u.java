package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import androidx.core.app.W;
import com.google.android.gms.internal.mlkit_vision_camera.L1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.data.model.U0;
import com.quizlet.features.practicetest.PracticeTestActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String c;
    public final String a;
    public final String b;

    static {
        String simpleName = u.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        c = simpleName;
    }

    public u(String uuid, String path) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(path, "path");
        this.a = uuid;
        this.b = path;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intent intentC;
        Intrinsics.checkNotNullParameter(context, "context");
        boolean zEquals = this.b.equals("practice-test");
        String str = this.a;
        if (zEquals) {
            int i = PracticeTestActivity.h;
            intentC = L1.d(context, str, U0.f);
        } else {
            int i2 = PracticeTestActivity.h;
            intentC = L1.c(context, str);
        }
        W w = new W(context);
        w.a(intentC);
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
        if (!(obj instanceof u)) {
            return false;
        }
        u uVar = (u) obj;
        return Intrinsics.b(this.a, uVar.a) && Intrinsics.b(this.b, uVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return c;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestsDeepLink(uuid=");
        sb.append(this.a);
        sb.append(", path=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
