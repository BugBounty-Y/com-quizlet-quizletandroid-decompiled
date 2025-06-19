package com.quizlet.features.paywall;

import android.app.Activity;
import android.os.Bundle;
import androidx.activity.O;
import androidx.activity.P;
import androidx.activity.compose.j;
import androidx.activity.v;
import androidx.appcompat.app.C0054j;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.features.infra.navigation.A;
import com.quizlet.quizletandroid.R;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class PaywallActivity extends com.quizlet.baseui.base.c implements dagger.hilt.internal.b {
    public static final /* synthetic */ int l = 0;
    public com.quizlet.login.authentication.login.a d;
    public volatile dagger.hilt.android.internal.managers.b e;
    public final Object f = new Object();
    public boolean g = false;
    public final String h;
    public A i;
    public final u j;
    public final u k;

    public PaywallActivity() {
        addOnContextAvailableListener(new C0054j(this, 16));
        this.h = "PaywallActivity";
        final int i = 0;
        this.j = l.b(new Function0(this) { // from class: com.quizlet.features.paywall.a
            public final /* synthetic */ PaywallActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                PaywallActivity paywallActivity = this.b;
                switch (i) {
                    case 0:
                        int i2 = PaywallActivity.l;
                        String stringExtra = paywallActivity.getIntent().getStringExtra("upgradeSource");
                        if (stringExtra != null) {
                            return stringExtra;
                        }
                        throw new IllegalArgumentException("Required value was null.");
                    default:
                        int i3 = PaywallActivity.l;
                        retrofit2.adapter.rxjava3.d dVar = com.quizlet.features.infra.models.upgrade.a.b;
                        int intExtra = paywallActivity.getIntent().getIntExtra("navigationSource", -1);
                        dVar.getClass();
                        for (com.quizlet.features.infra.models.upgrade.a aVar : com.quizlet.features.infra.models.upgrade.a.values()) {
                            if (aVar.a == intExtra) {
                                return aVar;
                            }
                        }
                        throw new NoSuchElementException("Array contains no element matching the predicate.");
                }
            }
        });
        final int i2 = 1;
        this.k = l.b(new Function0(this) { // from class: com.quizlet.features.paywall.a
            public final /* synthetic */ PaywallActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                PaywallActivity paywallActivity = this.b;
                switch (i2) {
                    case 0:
                        int i22 = PaywallActivity.l;
                        String stringExtra = paywallActivity.getIntent().getStringExtra("upgradeSource");
                        if (stringExtra != null) {
                            return stringExtra;
                        }
                        throw new IllegalArgumentException("Required value was null.");
                    default:
                        int i3 = PaywallActivity.l;
                        retrofit2.adapter.rxjava3.d dVar = com.quizlet.features.infra.models.upgrade.a.b;
                        int intExtra = paywallActivity.getIntent().getIntExtra("navigationSource", -1);
                        dVar.getClass();
                        for (com.quizlet.features.infra.models.upgrade.a aVar : com.quizlet.features.infra.models.upgrade.a.values()) {
                            if (aVar.a == intExtra) {
                                return aVar;
                            }
                        }
                        throw new NoSuchElementException("Array contains no element matching the predicate.");
                }
            }
        });
    }

    public final void B(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = z().b();
            this.d = aVarB;
            if (aVarB.l()) {
                this.d.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return z().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        B(bundle);
        int iA = com.quizlet.themes.extensions.a.a(this, R.attr.RefColorTwilight900);
        v.b(this, new P(iA, iA, 2, O.c), 2);
        j.a(this, new androidx.compose.runtime.internal.d(true, -729416806, new b(this, 1)));
    }

    @Override // com.quizlet.baseui.base.c, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.d;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return this.h;
    }

    public final dagger.hilt.android.internal.managers.b z() {
        if (this.e == null) {
            synchronized (this.f) {
                try {
                    if (this.e == null) {
                        this.e = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.e;
    }
}
