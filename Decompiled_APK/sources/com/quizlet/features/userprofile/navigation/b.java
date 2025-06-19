package com.quizlet.features.userprofile.navigation;

import com.quizlet.features.infra.navigation.A;
import com.quizlet.features.infra.navigation.InterfaceC4341a;
import com.quizlet.features.infra.navigation.InterfaceC4342b;
import com.quizlet.features.infra.navigation.InterfaceC4343c;
import com.quizlet.features.infra.navigation.v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements InterfaceC4343c, v, InterfaceC4341a, A, InterfaceC4342b {
    public final /* synthetic */ InterfaceC4343c a;
    public final /* synthetic */ v b;
    public final /* synthetic */ InterfaceC4341a c;
    public final /* synthetic */ A d;
    public final /* synthetic */ InterfaceC4342b e;

    public b(InterfaceC4343c changeUserImageNavigation, v settingsNavigation, InterfaceC4341a achievementsNavigation, A upgradeNavigation, InterfaceC4342b activityNavigation) {
        Intrinsics.checkNotNullParameter(changeUserImageNavigation, "changeUserImageNavigation");
        Intrinsics.checkNotNullParameter(settingsNavigation, "settingsNavigation");
        Intrinsics.checkNotNullParameter(achievementsNavigation, "achievementsNavigation");
        Intrinsics.checkNotNullParameter(upgradeNavigation, "upgradeNavigation");
        Intrinsics.checkNotNullParameter(activityNavigation, "activityNavigation");
        this.a = changeUserImageNavigation;
        this.b = settingsNavigation;
        this.c = achievementsNavigation;
        this.d = upgradeNavigation;
        this.e = activityNavigation;
    }

    @Override // com.quizlet.features.infra.navigation.InterfaceC4343c
    public final void a(String profileImageId, boolean z, androidx.activity.result.b launcher) {
        Intrinsics.checkNotNullParameter(profileImageId, "profileImageId");
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        this.a.a(profileImageId, z, launcher);
    }

    @Override // com.quizlet.features.infra.navigation.v
    public final void b() {
        this.b.b();
    }

    @Override // com.quizlet.features.infra.navigation.InterfaceC4342b
    public final void c() {
        this.e.c();
    }

    @Override // com.quizlet.features.infra.navigation.InterfaceC4341a
    public final void e() {
        this.c.e();
    }

    @Override // com.quizlet.features.infra.navigation.A
    public final void i(String upgradeSource, com.quizlet.features.infra.models.upgrade.a navigationSource, androidx.activity.result.b bVar) {
        Intrinsics.checkNotNullParameter(upgradeSource, "upgradeSource");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        this.d.i(upgradeSource, navigationSource, bVar);
    }
}
