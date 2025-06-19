package com.quizlet.braze;

import com.braze.Braze;
import com.braze.enums.NotificationSubscriptionType;
import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e {
    public final Braze a;
    public final a b;

    public e(Braze braze, a sdkEnabler) {
        Intrinsics.checkNotNullParameter(braze, "braze");
        Intrinsics.checkNotNullParameter(sdkEnabler, "sdkEnabler");
        this.a = braze;
        this.b = sdkEnabler;
    }

    public final void a(DBUser user) {
        Intrinsics.checkNotNullParameter(user, "user");
        boolean isUnderAge = user.getIsUnderAge();
        a aVar = this.b;
        if (isUnderAge) {
            c cVar = (c) aVar;
            cVar.getClass();
            Braze.Companion.disableSdk(cVar.a);
        } else {
            c cVar2 = (c) aVar;
            cVar2.getClass();
            Braze.Companion.enableSdk(cVar2.a);
            this.a.changeUser(String.valueOf(user.getId()));
        }
    }

    public final void b(boolean z) {
        this.a.getCurrentUser(new d(z ? NotificationSubscriptionType.SUBSCRIBED : NotificationSubscriptionType.UNSUBSCRIBED));
    }
}
