package com.quizlet.quizletandroid.ui.profile;

import android.view.View;
import androidx.lifecycle.p0;
import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ ProfileFragment b;

    public /* synthetic */ e(ProfileFragment profileFragment, int i) {
        this.a = i;
        this.b = profileFragment;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        ProfileFragment profileFragment = this.b;
        switch (this.a) {
            case 0:
                String str = ProfileFragment.x;
                com.quizlet.quizletandroid.ui.profile.data.h hVarX = profileFragment.X();
                hVarX.getClass();
                E.A(p0.j(hVarX), null, null, new com.quizlet.quizletandroid.ui.profile.data.g(hVarX, null), 3);
                break;
            case 1:
                String str2 = ProfileFragment.x;
                com.quizlet.quizletandroid.ui.profile.data.h hVarX2 = profileFragment.X();
                com.quizlet.features.userprofile.a aVar = hVarX2.i;
                aVar.getClass();
                aVar.a.l(com.quizlet.features.userprofile.a.a("clicked_upgrade"));
                if (hVarX2.g.r != null) {
                    com.quizlet.features.infra.models.upgrade.a navigationSource = com.quizlet.features.infra.models.upgrade.a.r;
                    Intrinsics.checkNotNullParameter("chiclet", "upgradeSource");
                    Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
                    hVarX2.l.j(new k());
                    break;
                }
                break;
            default:
                String str3 = ProfileFragment.x;
                com.quizlet.quizletandroid.ui.profile.data.h hVarX3 = profileFragment.X();
                com.quizlet.infra.legacysyncengine.managers.d dVar = hVarX3.g;
                DBUser dBUser = dVar.r;
                String profileImageId = dBUser != null ? dBUser.getProfileImageId() : null;
                if (hVarX3.C(hVarX3.n) && profileImageId != null) {
                    DBUser dBUser2 = dVar.r;
                    boolean z = false;
                    if (dBUser2 != null && !dBUser2.getIsUnderAge()) {
                        z = true;
                    }
                    hVarX3.l.j(new i(profileImageId, z));
                    break;
                }
                break;
        }
    }
}
