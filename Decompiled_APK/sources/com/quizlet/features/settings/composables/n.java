package com.quizlet.features.settings.composables;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n {
    public final Function1 a;
    public final Function1 b;
    public final Function0 c;

    public n(Function1 onPushNotificationsCheckedChanged, Function1 onSoundEffectsCheckedChanged, Function0 onAdsAndCookiesClicked) {
        Intrinsics.checkNotNullParameter(onPushNotificationsCheckedChanged, "onPushNotificationsCheckedChanged");
        Intrinsics.checkNotNullParameter(onSoundEffectsCheckedChanged, "onSoundEffectsCheckedChanged");
        Intrinsics.checkNotNullParameter(onAdsAndCookiesClicked, "onAdsAndCookiesClicked");
        this.a = onPushNotificationsCheckedChanged;
        this.b = onSoundEffectsCheckedChanged;
        this.c = onAdsAndCookiesClicked;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && Intrinsics.b(this.b, nVar.b) && Intrinsics.b(this.c, nVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "PreferencesActions(onPushNotificationsCheckedChanged=" + this.a + ", onSoundEffectsCheckedChanged=" + this.b + ", onAdsAndCookiesClicked=" + this.c + ")";
    }
}
