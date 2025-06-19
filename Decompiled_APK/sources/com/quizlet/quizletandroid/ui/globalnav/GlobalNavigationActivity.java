package com.quizlet.quizletandroid.ui.globalnav;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcelable;
import androidx.fragment.app.AbstractC1136h0;
import androidx.lifecycle.p0;
import com.quizlet.features.emailconfirmation.ui.activities.l;
import com.quizlet.quizletandroid.ui.common.ads.G;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.v;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.A;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;

@Metadata
/* loaded from: classes3.dex */
public final class GlobalNavigationActivity extends l {
    public static final String u;
    public com.quizlet.quizletandroid.ui.globalnav.navigation.a p;
    public com.quizlet.data.repository.classfolder.e q;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e r;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e s;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e t;

    static {
        Intrinsics.checkNotNullExpressionValue("GlobalNavigationActivity", "getSimpleName(...)");
        u = "GlobalNavigationActivity";
    }

    public GlobalNavigationActivity() {
        super(3);
        this.r = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.globalnav.viewmodel.e.class), new i(this, 1), new i(this, 0), new i(this, 2));
        this.s = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(L.class), new i(this, 4), new i(this, 3), new i(this, 5));
        this.t = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.login.magiclink.viewmodel.g.class), new i(this, 7), new i(this, 6), new i(this, 8));
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return u;
    }

    public final void P() {
        GlobalNavReroute globalNavReroute;
        String stringExtra = getIntent().getStringExtra("GlobalNav.magicLinkCode");
        if (stringExtra != null) {
            Intent intent = getIntent();
            intent.removeExtra("GlobalNav.magicLinkCode");
            setIntent(intent);
            com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar = this.p;
            if (aVar == null) {
                Intrinsics.m("navigationManager");
                throw null;
            }
            AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "getSupportFragmentManager(...)");
            aVar.h(supportFragmentManager, stringExtra);
            return;
        }
        if (getIntent().hasExtra("GlobalNav.navReroute")) {
            Parcelable parcelableExtra = getIntent().getParcelableExtra("GlobalNav.navReroute");
            globalNavReroute = parcelableExtra instanceof GlobalNavReroute ? (GlobalNavReroute) parcelableExtra : null;
            Intent intent2 = getIntent();
            intent2.removeExtra("GlobalNav.navReroute");
            setIntent(intent2);
        } else {
            globalNavReroute = null;
        }
        L l = (L) this.s.getValue();
        com.quizlet.login.common.interactors.d dVar = l.c;
        if (((com.quizlet.db.b) dVar.b).a.getString("upgrade_target", null) == null) {
            E.A(p0.j(l), null, null, new com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.K(globalNavReroute, l, null), 3);
            return;
        }
        d0 d0Var = l.p;
        v navigationSource = v.a;
        Intrinsics.checkNotNullParameter("DEEP_LINK", "upgradeSource");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        d0Var.h(new A());
        ((com.quizlet.db.b) dVar.b).a.edit().putString("upgrade_target", null).apply();
    }

    @Override // com.quizlet.features.emailconfirmation.ui.activities.l, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        androidx.activity.v.b(this, null, 3);
        androidx.activity.compose.j.a(this, new androidx.compose.runtime.internal.d(true, -1626297594, new a(this, 1)));
        com.quizlet.data.repository.classfolder.e eVar = this.q;
        if (eVar == null) {
            Intrinsics.m("pushNotificationPermissionHandler");
            throw null;
        }
        Intrinsics.checkNotNullParameter(this, "activity");
        eVar.d = registerForActivityResult(new androidx.activity.result.contract.b(3), new androidx.activity.compose.b(eVar, 5));
        E.A(p0.h(this), null, null, new d(this, null), 3);
        ((L) this.s.getValue()).s.f(this, new com.quizlet.ads.ui.fragments.c(new G(this, 6)));
        E.A(p0.h(this), null, null, new f(this, null), 3);
        E.A(p0.h(this), null, null, new h(this, null), 3);
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onNewIntent(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        super.onNewIntent(intent);
        setIntent(intent);
        P();
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return 0;
    }
}
