package com.quizlet.baseui.events;

import android.content.Intent;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final Intent a;

    public a(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        this.a = intent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof a) {
            return Intrinsics.b(this.a, ((a) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Boolean.hashCode(false) + (this.a.hashCode() * 29791);
    }

    public final String toString() {
        return "IntentEvent(intent=" + this.a + ", resultCode=null, requestCode=null, shouldFinish=false)";
    }
}
