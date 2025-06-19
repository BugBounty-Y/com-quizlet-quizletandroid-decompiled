package com.quizlet.upgrade.ui.activity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import androidx.activity.M;
import androidx.activity.O;
import androidx.activity.P;
import androidx.activity.v;
import androidx.appcompat.widget.Toolbar;
import androidx.compose.ui.node.B;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.FragmentContainerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3699p6;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.navigationmanagers.i;
import com.quizlet.quizletandroid.util.g;
import com.quizlet.search.composables.E;
import com.quizlet.upgrade.data.o;
import com.quizlet.upgrade.ui.fragment.UpgradeFragment;
import java.io.Serializable;
import java.util.WeakHashMap;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class UpgradeActivity extends com.quizlet.ads.ui.activity.d {
    public static final String v;
    public i q;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e r;
    public final u s;
    public final u t;
    public final u u;

    static {
        Intrinsics.checkNotNullExpressionValue("UpgradeActivity", "getSimpleName(...)");
        v = "UpgradeActivity";
    }

    public UpgradeActivity() {
        super(14);
        this.r = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.upgrade.ui.confirmation.c.class), new d(this, 1), new d(this, 0), new d(this, 2));
        final int i = 0;
        this.s = l.b(new Function0(this) { // from class: com.quizlet.upgrade.ui.activity.b
            public final /* synthetic */ UpgradeActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                UpgradeActivity upgradeActivity = this.b;
                switch (i) {
                    case 0:
                        String str = UpgradeActivity.v;
                        Serializable serializableExtra = upgradeActivity.getIntent().getSerializableExtra("NavigationSource");
                        com.quizlet.features.infra.models.upgrade.a aVar = serializableExtra instanceof com.quizlet.features.infra.models.upgrade.a ? (com.quizlet.features.infra.models.upgrade.a) serializableExtra : null;
                        com.quizlet.features.infra.models.upgrade.a.b.getClass();
                        return Boolean.valueOf(CollectionsKt.F(com.quizlet.features.infra.models.upgrade.a.d, aVar));
                    case 1:
                        String str2 = UpgradeActivity.v;
                        return Boolean.valueOf(upgradeActivity.getIntent().getBooleanExtra("skipToPlansState", false));
                    default:
                        String str3 = UpgradeActivity.v;
                        return upgradeActivity.getIntent().getStringExtra("UpgradeSource");
                }
            }
        });
        final int i2 = 1;
        this.t = l.b(new Function0(this) { // from class: com.quizlet.upgrade.ui.activity.b
            public final /* synthetic */ UpgradeActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                UpgradeActivity upgradeActivity = this.b;
                switch (i2) {
                    case 0:
                        String str = UpgradeActivity.v;
                        Serializable serializableExtra = upgradeActivity.getIntent().getSerializableExtra("NavigationSource");
                        com.quizlet.features.infra.models.upgrade.a aVar = serializableExtra instanceof com.quizlet.features.infra.models.upgrade.a ? (com.quizlet.features.infra.models.upgrade.a) serializableExtra : null;
                        com.quizlet.features.infra.models.upgrade.a.b.getClass();
                        return Boolean.valueOf(CollectionsKt.F(com.quizlet.features.infra.models.upgrade.a.d, aVar));
                    case 1:
                        String str2 = UpgradeActivity.v;
                        return Boolean.valueOf(upgradeActivity.getIntent().getBooleanExtra("skipToPlansState", false));
                    default:
                        String str3 = UpgradeActivity.v;
                        return upgradeActivity.getIntent().getStringExtra("UpgradeSource");
                }
            }
        });
        final int i3 = 2;
        this.u = l.b(new Function0(this) { // from class: com.quizlet.upgrade.ui.activity.b
            public final /* synthetic */ UpgradeActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                UpgradeActivity upgradeActivity = this.b;
                switch (i3) {
                    case 0:
                        String str = UpgradeActivity.v;
                        Serializable serializableExtra = upgradeActivity.getIntent().getSerializableExtra("NavigationSource");
                        com.quizlet.features.infra.models.upgrade.a aVar = serializableExtra instanceof com.quizlet.features.infra.models.upgrade.a ? (com.quizlet.features.infra.models.upgrade.a) serializableExtra : null;
                        com.quizlet.features.infra.models.upgrade.a.b.getClass();
                        return Boolean.valueOf(CollectionsKt.F(com.quizlet.features.infra.models.upgrade.a.d, aVar));
                    case 1:
                        String str2 = UpgradeActivity.v;
                        return Boolean.valueOf(upgradeActivity.getIntent().getBooleanExtra("skipToPlansState", false));
                    default:
                        String str3 = UpgradeActivity.v;
                        return upgradeActivity.getIntent().getStringExtra("UpgradeSource");
                }
            }
        });
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return v;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_upgrade_v2, (ViewGroup) null, false);
        int i = R.id.container;
        FragmentContainerView fragmentContainerView = (FragmentContainerView) AbstractC3375o2.c(R.id.container, viewInflate);
        if (fragmentContainerView != null) {
            i = R.id.loadingProgress;
            if (((ProgressBar) AbstractC3375o2.c(R.id.loadingProgress, viewInflate)) != null) {
                i = R.id.toolbar;
                Toolbar toolbar = (Toolbar) AbstractC3375o2.c(R.id.toolbar, viewInflate);
                if (toolbar != null) {
                    com.quizlet.upgrade.databinding.a aVar = new com.quizlet.upgrade.databinding.a((ConstraintLayout) viewInflate, fragmentContainerView, toolbar);
                    Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
                    return aVar;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void b0(o oVar) {
        Integer num = oVar.a;
        if (num != null) {
            int iIntValue = num.intValue();
            Intent intent = new Intent();
            intent.putExtra("ResultUserUpgradeType", iIntValue);
            setResult(-1, intent);
        }
        i iVar = this.q;
        if (iVar == null) {
            Intrinsics.m("navigationManager");
            throw null;
        }
        boolean z = oVar.a != null;
        Intrinsics.checkNotNullParameter(this, "activity");
        if (z && Intrinsics.b(getIntent().getAction(), "require_email_confirmation")) {
            getIntent().setAction("open_start_activity");
        }
        iVar.a.getClass();
        g.a(this, null);
    }

    public final void c0(BaseFragment baseFragment) {
        if (getSupportFragmentManager().E(baseFragment.N()) == null) {
            AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
            C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
            c1121aB.l(((com.quizlet.upgrade.databinding.a) K()).b.getId(), baseFragment, baseFragment.N());
            c1121aB.g();
        }
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        AbstractC3699p6.b(this, R.attr.SysColorSurface);
        int iA = com.quizlet.themes.extensions.a.a(this, R.attr.RefColorTwilight900);
        v.b(this, new P(iA, iA, 2, O.c), 2);
        getOnBackPressedDispatcher().a(this, new M(this));
        com.quizlet.upgrade.databinding.a aVar = (com.quizlet.upgrade.databinding.a) K();
        a aVar2 = new a(this);
        WeakHashMap weakHashMap = V.a;
        L.m(aVar.a, aVar2);
        ((com.quizlet.upgrade.databinding.a) K()).c.setNavigationIcon(com.quizlet.themes.extensions.a.c(this, R.drawable.ic_sys_close_x, R.attr.AssemblyGray100));
        com.quizlet.upgrade.databinding.a aVar3 = (com.quizlet.upgrade.databinding.a) K();
        aVar3.c.setNavigationOnClickListener(new c(this, 0));
        ((com.quizlet.upgrade.ui.confirmation.c) this.r.getValue()).b.f(this, new com.quizlet.ads.ui.fragments.c(new E(1, this, UpgradeActivity.class, "onNavigationEvent", "onNavigationEvent(Lcom/quizlet/upgrade/data/UpgradeNavigationEvent;)V", 0, 2)));
        String str = UpgradeFragment.r;
        boolean zBooleanValue = ((Boolean) this.s.getValue()).booleanValue();
        boolean zBooleanValue2 = ((Boolean) this.t.getValue()).booleanValue();
        String str2 = (String) this.u.getValue();
        UpgradeFragment upgradeFragment = new UpgradeFragment();
        Bundle bundle2 = new Bundle();
        bundle2.putBoolean("isAfterSignUp", zBooleanValue);
        bundle2.putBoolean("skipToPlansState", zBooleanValue2);
        bundle2.putString("UpgradeSource", str2);
        upgradeFragment.setArguments(bundle2);
        c0(upgradeFragment);
        getSupportFragmentManager().h0("UpgradeFragmentRequestKey", this, new a(this));
    }
}
