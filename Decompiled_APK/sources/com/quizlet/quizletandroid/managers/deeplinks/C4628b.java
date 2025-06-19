package com.quizlet.quizletandroid.managers.deeplinks;

import android.app.TaskStackBuilder;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3697p4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.managers.deeplinks.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4628b extends AbstractC3697p4 {
    public static final String b;
    public final long a;

    static {
        String simpleName = C4628b.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public C4628b(long j) {
        this.a = j;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intent[] intents = TaskStackBuilder.create(context).addNextIntentWithParentStack(D4.a(context, new GlobalNavReroute.AchievementsProfile(this.a, null))).getIntents();
        Intrinsics.checkNotNullExpressionValue(intents, "getIntents(...)");
        return intents;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4628b) && this.a == ((C4628b) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return b;
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("AchievementsProfileDeepLink(userId="));
    }
}
