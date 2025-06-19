package com.quizlet.quizletandroid.ui.studymodes.write;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.os.Bundle;
import android.widget.FrameLayout;
import androidx.activity.v;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.l0;

/* loaded from: classes3.dex */
public class WriteSettingsActivity extends com.quizlet.baseui.base.f implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final /* synthetic */ int u = 0;
    public WriteStudyModeConfig l;
    public int m;
    public boolean n;
    public String o;
    public String p;
    public com.quizlet.login.authentication.login.a q;
    public volatile dagger.hilt.android.internal.managers.b r;
    public final Object s = new Object();
    public boolean t = false;

    public WriteSettingsActivity() {
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i(this, 29));
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return "WriteSettingsActivity";
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        return l0.a(getLayoutInflater());
    }

    public final dagger.hilt.android.internal.managers.b O() {
        if (this.r == null) {
            synchronized (this.s) {
                try {
                    if (this.r == null) {
                        this.r = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.r;
    }

    public final void P(Bundle bundle) {
        super.onCreate(bundle);
        v.a(this);
        AbstractC3188k6.a(((l0) this.k).a);
        Bundle extras = getIntent().getExtras();
        if (extras == null) {
            throw new IllegalStateException("No extras provided to WriteSettingsActivity");
        }
        this.l = (WriteStudyModeConfig) extras.getParcelable("learnModeConfig");
        this.m = extras.getInt("selectedTermCount");
        this.n = extras.getBoolean("showImageOptions");
        this.o = extras.getString("studyableWordLanguageCode");
        this.p = extras.getString("studyableDefinitionLanguageCode");
        ((FrameLayout) ((l0) K()).c.c).setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 21));
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return O().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof dagger.hilt.internal.b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        WriteSettingsFragment writeSettingsFragment = (WriteSettingsFragment) getSupportFragmentManager().E("WriteSettingsFragment");
        if (writeSettingsFragment != null) {
            writeSettingsFragment.R(false);
        }
        super.onBackPressed();
    }

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        P(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = O().b();
            this.q = aVarB;
            if (aVarB.l()) {
                this.q.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.q;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        setTitle(R.string.study_mode_options);
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() {
        super.onStart();
        if (getSupportFragmentManager().E("WriteSettingsFragment") == null) {
            WriteStudyModeConfig writeStudyModeConfig = this.l;
            int i = this.m;
            boolean z = this.n;
            String str = this.o;
            String str2 = this.p;
            WriteSettingsFragment writeSettingsFragment = new WriteSettingsFragment();
            Bundle bundle = new Bundle();
            bundle.putParcelable("learnModeConfig", writeStudyModeConfig);
            bundle.putInt("selectedTermCount", i);
            bundle.putBoolean("showImageOptions", z);
            bundle.putString("studyableWordLanguageCode", str);
            bundle.putString("studyableDefinitionLanguageCode", str2);
            writeSettingsFragment.setArguments(bundle);
            AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
            supportFragmentManager.getClass();
            C1121a c1121a = new C1121a(supportFragmentManager);
            c1121a.i(R.id.fragment_container, writeSettingsFragment, "WriteSettingsFragment", 1);
            c1121a.g();
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.t;
    }
}
