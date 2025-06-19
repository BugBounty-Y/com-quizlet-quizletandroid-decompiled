package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import androidx.activity.v;
import androidx.compose.ui.node.B;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.setcreation.fragments.ScanDocumentFragment;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class ScanDocumentActivity extends com.quizlet.baseui.base.b implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final /* synthetic */ int o = 0;
    public com.quizlet.login.authentication.login.a k;
    public volatile dagger.hilt.android.internal.managers.b l;
    public final Object m = new Object();
    public boolean n = false;

    public ScanDocumentActivity() {
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i(this, 19));
    }

    @Override // com.quizlet.baseui.base.b
    public final Integer B() {
        return Integer.valueOf(R.menu.scan_document_menu);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return "ScanDocumentActivity";
    }

    public final dagger.hilt.android.internal.managers.b J() {
        if (this.l == null) {
            synchronized (this.m) {
                try {
                    if (this.l == null) {
                        this.l = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.l;
    }

    public final void K(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = J().b();
            this.k = aVarB;
            if (aVarB.l()) {
                this.k.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return J().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof dagger.hilt.internal.b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        Fragment fragmentD = getSupportFragmentManager().D(R.id.scan_document_ocr_container);
        Intrinsics.e(fragmentD, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.setcreation.fragments.ScanDocumentFragment");
        ((ScanDocumentFragment) fragmentD).T();
        super.onBackPressed();
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Bundle extras;
        K(bundle);
        v.b(this, null, 3);
        View viewFindViewById = findViewById(R.id.parent_container);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "findViewById(...)");
        AbstractC3188k6.a(viewFindViewById);
        if (bundle == null) {
            Intent intent = getIntent();
            Long lValueOf = (intent == null || (extras = intent.getExtras()) == null) ? null : Long.valueOf(extras.getLong("setId"));
            if (lValueOf != null) {
                AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
                C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                long jLongValue = lValueOf.longValue();
                ScanDocumentFragment scanDocumentFragment = new ScanDocumentFragment();
                Bundle bundle2 = new Bundle();
                bundle2.putLong("setId", jLongValue);
                scanDocumentFragment.setArguments(bundle2);
                c1121aB.i(R.id.scan_document_ocr_container, scanDocumentFragment, null, 1);
                c1121aB.g();
            }
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.k;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.n;
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return R.layout.activity_scan_document;
    }
}
