package com.braze.events.internal;

import com.braze.models.inappmessage.IInAppMessage;
import com.braze.support.JsonUtils;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m {
    public final com.braze.triggers.events.b a;
    public final com.braze.triggers.actions.h b;
    public final IInAppMessage c;
    public final String d;

    public m(com.braze.triggers.events.b triggerEvent, com.braze.triggers.actions.h triggeredAction, IInAppMessage inAppMessage, String str) {
        Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
        Intrinsics.checkNotNullParameter(triggeredAction, "triggeredAction");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        this.a = triggerEvent;
        this.b = triggeredAction;
        this.c = inAppMessage;
        this.d = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.a, mVar.a) && Intrinsics.b(this.b, mVar.b) && Intrinsics.b(this.c, mVar.c) && Intrinsics.b(this.d, mVar.d);
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31;
        String str = this.d;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        return kotlin.text.x.c("\n             " + JsonUtils.getPrettyPrintedString(this.c.forJsonPut()) + "\n             Triggered Action Id: " + this.b.a + "\n             Trigger Event: " + this.a + "\n             User Id: " + this.d + "\n        ");
    }
}
