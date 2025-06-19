package com.quizlet.quizletandroid.ui.usersettings.activities;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.os.Bundle;
import android.view.View;
import androidx.activity.v;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeProfileImageFragment;
import java.lang.reflect.InvocationTargetException;
import java.util.WeakHashMap;
import kotlin.Pair;

/* loaded from: classes3.dex */
public class ChangeProfileImageActivity extends b implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final /* synthetic */ int q = 0;
    public com.quizlet.login.authentication.login.a k;
    public volatile dagger.hilt.android.internal.managers.b l;
    public final Object m = new Object();
    public boolean n = false;
    public String o;
    public boolean p;

    public ChangeProfileImageActivity() {
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.subject.c(this, 1));
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return "ChangeProfileImageActivity";
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

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        K(bundle);
        v.a(this);
        View viewFindViewById = findViewById(R.id.appbar);
        com.quizlet.quizletandroid.ui.setcreation.imageupload.a aVar = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(17);
        WeakHashMap weakHashMap = V.a;
        L.m(viewFindViewById, aVar);
        if (getIntent().getExtras() != null) {
            this.o = getIntent().getExtras().getString("EXTRA_PROFILE_IMAGE_ID");
            this.p = getIntent().getExtras().getBoolean("EXTRA_ALLOW_CUSTOM_IMAGES");
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

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() {
        super.onStart();
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        String str = ChangeProfileImageFragment.w;
        if (supportFragmentManager.E(str) == null) {
            String str2 = this.o;
            boolean z = this.p;
            ChangeProfileImageFragment changeProfileImageFragment = new ChangeProfileImageFragment();
            changeProfileImageFragment.setArguments(AbstractC3206m6.a(new Pair("ARG_PROFILE_IMAGE_ID", str2), new Pair("ARG_ALLOW_CUSTOM_IMAGES", Boolean.valueOf(z))));
            AbstractC1136h0 supportFragmentManager2 = getSupportFragmentManager();
            supportFragmentManager2.getClass();
            C1121a c1121a = new C1121a(supportFragmentManager2);
            c1121a.i(R.id.fragment_container, changeProfileImageFragment, str, 1);
            c1121a.g();
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.n;
    }
}
