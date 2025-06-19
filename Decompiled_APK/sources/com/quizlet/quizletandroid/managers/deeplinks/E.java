package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.quizletandroid.ui.profile.ProfileActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class E implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String c;
    public final long a;
    public final int b;

    static {
        String simpleName = E.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        c = simpleName;
    }

    public E(int i, long j) {
        this.a = j;
        this.b = i;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        long j = this.a;
        int i = this.b;
        if (i == 0) {
            com.quizlet.quizletandroid.ui.profile.b bVar = ProfileActivity.p;
            Intrinsics.checkNotNullParameter(context, "context");
            return new Intent[]{com.quizlet.quizletandroid.ui.profile.b.i(bVar, context, j, 0)};
        }
        if (i == 1) {
            com.quizlet.quizletandroid.ui.profile.b bVar2 = ProfileActivity.p;
            Intrinsics.checkNotNullParameter(context, "context");
            return new Intent[]{com.quizlet.quizletandroid.ui.profile.b.i(bVar2, context, j, 1)};
        }
        if (i != 3) {
            return new Intent[]{ProfileActivity.p.g(context, j)};
        }
        com.quizlet.quizletandroid.ui.profile.b bVar3 = ProfileActivity.p;
        Intrinsics.checkNotNullParameter(context, "context");
        return new Intent[]{com.quizlet.quizletandroid.ui.profile.b.i(bVar3, context, j, 3)};
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

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("UserDeepLink("));
    }
}
