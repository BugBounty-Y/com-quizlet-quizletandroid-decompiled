package com.quizlet.features.onboarding.navigation;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import androidx.activity.result.ActivityResult;
import androidx.activity.s;
import androidx.activity.v;
import androidx.appcompat.app.C0054j;
import androidx.lifecycle.p0;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.features.infra.navigation.A;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class OnboardingNavigationActivity extends s implements dagger.hilt.internal.b {
    public static final /* synthetic */ int j = 0;
    public com.quizlet.login.authentication.login.a a;
    public volatile dagger.hilt.android.internal.managers.b b;
    public final Object c = new Object();
    public boolean d = false;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e e;
    public androidx.activity.result.b f;
    public androidx.activity.result.b g;
    public androidx.activity.result.b h;
    public A i;

    public OnboardingNavigationActivity() {
        addOnContextAvailableListener(new C0054j(this, 14));
        this.e = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(p.class), new e(this, 1), new e(this, 0), new e(this, 2));
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return o().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    public final dagger.hilt.android.internal.managers.b o() {
        if (this.b == null) {
            synchronized (this.c) {
                try {
                    if (this.b == null) {
                        this.b = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.b;
    }

    @Override // androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        q(bundle);
        v.b(this, null, 3);
        final int i = 0;
        this.f = registerForActivityResult(new androidx.activity.result.contract.b(4), new androidx.activity.result.a(this) { // from class: com.quizlet.features.onboarding.navigation.b
            public final /* synthetic */ OnboardingNavigationActivity b;

            {
                this.b = this;
            }

            @Override // androidx.activity.result.a
            public final void a(Object obj) {
                Intent intent;
                OnboardingNavigationActivity onboardingNavigationActivity = this.b;
                Integer numValueOf = null;
                ActivityResult it2 = (ActivityResult) obj;
                switch (i) {
                    case 0:
                        int i2 = OnboardingNavigationActivity.j;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        p.B((p) onboardingNavigationActivity.e.getValue(), l.c, null, 6);
                        break;
                    case 1:
                        int i3 = OnboardingNavigationActivity.j;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        p.B((p) onboardingNavigationActivity.e.getValue(), l.b, null, 6);
                        break;
                    default:
                        int i4 = OnboardingNavigationActivity.j;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a == -1 && (intent = it2.b) != null) {
                            numValueOf = Integer.valueOf(intent.getIntExtra("ResultUserUpgradeType", 0));
                        }
                        p.B((p) onboardingNavigationActivity.e.getValue(), l.d, numValueOf, 2);
                        break;
                }
            }
        });
        final int i2 = 1;
        this.g = registerForActivityResult(new androidx.activity.result.contract.b(4), new androidx.activity.result.a(this) { // from class: com.quizlet.features.onboarding.navigation.b
            public final /* synthetic */ OnboardingNavigationActivity b;

            {
                this.b = this;
            }

            @Override // androidx.activity.result.a
            public final void a(Object obj) {
                Intent intent;
                OnboardingNavigationActivity onboardingNavigationActivity = this.b;
                Integer numValueOf = null;
                ActivityResult it2 = (ActivityResult) obj;
                switch (i2) {
                    case 0:
                        int i22 = OnboardingNavigationActivity.j;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        p.B((p) onboardingNavigationActivity.e.getValue(), l.c, null, 6);
                        break;
                    case 1:
                        int i3 = OnboardingNavigationActivity.j;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        p.B((p) onboardingNavigationActivity.e.getValue(), l.b, null, 6);
                        break;
                    default:
                        int i4 = OnboardingNavigationActivity.j;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a == -1 && (intent = it2.b) != null) {
                            numValueOf = Integer.valueOf(intent.getIntExtra("ResultUserUpgradeType", 0));
                        }
                        p.B((p) onboardingNavigationActivity.e.getValue(), l.d, numValueOf, 2);
                        break;
                }
            }
        });
        final int i3 = 2;
        this.h = registerForActivityResult(new androidx.activity.result.contract.b(4), new androidx.activity.result.a(this) { // from class: com.quizlet.features.onboarding.navigation.b
            public final /* synthetic */ OnboardingNavigationActivity b;

            {
                this.b = this;
            }

            @Override // androidx.activity.result.a
            public final void a(Object obj) {
                Intent intent;
                OnboardingNavigationActivity onboardingNavigationActivity = this.b;
                Integer numValueOf = null;
                ActivityResult it2 = (ActivityResult) obj;
                switch (i3) {
                    case 0:
                        int i22 = OnboardingNavigationActivity.j;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        p.B((p) onboardingNavigationActivity.e.getValue(), l.c, null, 6);
                        break;
                    case 1:
                        int i32 = OnboardingNavigationActivity.j;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        p.B((p) onboardingNavigationActivity.e.getValue(), l.b, null, 6);
                        break;
                    default:
                        int i4 = OnboardingNavigationActivity.j;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (it2.a == -1 && (intent = it2.b) != null) {
                            numValueOf = Integer.valueOf(intent.getIntExtra("ResultUserUpgradeType", 0));
                        }
                        p.B((p) onboardingNavigationActivity.e.getValue(), l.d, numValueOf, 2);
                        break;
                }
            }
        });
        E.A(p0.h(this), null, null, new d(this, null), 3);
    }

    @Override // android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.a;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    public final void q(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = o().b();
            this.a = aVarB;
            if (aVarB.l()) {
                this.a.b = getDefaultViewModelCreationExtras();
            }
        }
    }
}
