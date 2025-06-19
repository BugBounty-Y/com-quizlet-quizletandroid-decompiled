package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import androidx.core.app.W;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.userprofile.ui.UserProfileActivity;
import com.quizlet.quizletandroid.ui.RootActivity;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.managers.deeplinks.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4629c implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String b;
    public final boolean a;

    static {
        String simpleName = C4629c.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public C4629c(boolean z) {
        this.a = z;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (!this.a) {
            return new Intent[]{new Intent(context, (Class<?>) RootActivity.class)};
        }
        W w = new W(context);
        String str = UserProfileActivity.j;
        Intent intentB = AbstractC4178x.b(context, "context", context, UserProfileActivity.class);
        intentB.putExtra("activityCenterReroute", true);
        w.a(intentB);
        return w.c();
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
