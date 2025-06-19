package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.content.Intent;
import android.graphics.PorterDuff;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import androidx.activity.v;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4605i;
import com.quizlet.quizletandroid.ui.FullScreenOverlayActivity;

/* loaded from: classes3.dex */
public class EditTermImagePreviewActivity extends FullScreenOverlayActivity implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final /* synthetic */ int t = 0;
    public com.quizlet.quizletandroid.sessionhelpers.a n;
    public UserInfoCache o;
    public com.quizlet.login.authentication.login.a p;
    public volatile dagger.hilt.android.internal.managers.b q;
    public final Object r = new Object();
    public boolean s = false;

    public EditTermImagePreviewActivity() {
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i(this, 17));
    }

    @Override // com.quizlet.baseui.base.b
    public final Integer B() {
        return Integer.valueOf(R.menu.edit_term_image_preview_menu);
    }

    public final dagger.hilt.android.internal.managers.b P() {
        if (this.q == null) {
            synchronized (this.r) {
                try {
                    if (this.q == null) {
                        this.q = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.q;
    }

    public final void Q(Bundle bundle) {
        super.onCreate(bundle);
        v.a(this);
        AbstractC3188k6.a(((C4605i) this.k).a);
        this.n = new com.quizlet.quizletandroid.sessionhelpers.a("img", getIntent());
        getLifecycle().a(this.n);
        this.n.h(bundle);
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return P().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof dagger.hilt.internal.b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        this.n.c(i, i2, intent);
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        setResult(-1, getIntent());
        super.onBackPressed();
    }

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        Q(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = P().b();
            this.p = aVarB;
            if (aVarB.l()) {
                this.p.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // com.quizlet.baseui.base.b, android.app.Activity
    public final boolean onCreateOptionsMenu(Menu menu) {
        super.onCreateOptionsMenu(menu);
        menu.findItem(R.id.menu_delete).getIcon().setColorFilter(com.quizlet.themes.extensions.a.a(this, R.attr.colorControlNormal), PorterDuff.Mode.SRC_ATOP);
        return true;
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.p;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // com.quizlet.baseui.base.b, android.app.Activity
    public final boolean onOptionsItemSelected(MenuItem menuItem) {
        if (menuItem.getItemId() != R.id.menu_delete) {
            return super.onOptionsItemSelected(menuItem);
        }
        setResult(1001, getIntent());
        finish();
        return true;
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onPause() {
        com.quizlet.quizletandroid.sessionhelpers.a aVar = this.n;
        getIntent().getLongExtra("termLocalId", 0L);
        getIntent().getLongExtra("termId", 0L);
        aVar.g();
        getIntent().putExtra("editSessionTrackerKey", this.n.a);
        super.onPause();
    }

    @Override // android.app.Activity
    public final boolean onPrepareOptionsMenu(Menu menu) {
        super.onPrepareOptionsMenu(menu);
        androidx.work.impl.model.f.b(menu, R.id.menu_delete, this.o.b());
        return true;
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onResume() {
        super.onResume();
        this.n.i("image", Long.valueOf(getIntent().getLongExtra("termLocalId", 0L)), Long.valueOf(getIntent().getLongExtra("termId", 0L)));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.s;
    }
}
