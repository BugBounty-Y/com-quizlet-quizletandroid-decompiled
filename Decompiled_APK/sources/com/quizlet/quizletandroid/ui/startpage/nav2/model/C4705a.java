package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.model.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4705a extends AbstractC4707c {
    public final androidx.camera.core.impl.utils.e d;

    public C4705a(androidx.camera.core.impl.utils.e streaksData) {
        Intrinsics.checkNotNullParameter(streaksData, "streaksData");
        this.d = streaksData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4705a) && Intrinsics.b(this.d, ((C4705a) obj).d);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "achievements_home_streaks_";
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return "AchievementsHomeData(streaksData=" + this.d + ")";
    }
}
