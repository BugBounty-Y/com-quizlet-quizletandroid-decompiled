package com.quizlet.quizletandroid.managers.deeplinks;

import android.app.TaskStackBuilder;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3697p4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.managers.deeplinks.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4627a extends AbstractC3697p4 {
    public static final String c;
    public final long a;
    public final String b;

    static {
        String simpleName = C4627a.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        c = simpleName;
    }

    public C4627a(long j, String badgeId) {
        Intrinsics.checkNotNullParameter(badgeId, "badgeId");
        this.a = j;
        this.b = badgeId;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intent[] intents = TaskStackBuilder.create(context).addNextIntentWithParentStack(D4.a(context, new GlobalNavReroute.AchievementsProfile(this.a, this.b))).getIntents();
        Intrinsics.checkNotNullExpressionValue(intents, "getIntents(...)");
        return intents;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4627a)) {
            return false;
        }
        C4627a c4627a = (C4627a) obj;
        return this.a == c4627a.a && Intrinsics.b(this.b, c4627a.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return c;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AchievementsBadgeDetailDeepLink(userId=");
        sb.append(this.a);
        sb.append(", badgeId=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
