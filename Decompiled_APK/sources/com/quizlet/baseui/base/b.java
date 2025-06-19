package com.quizlet.baseui.base;

import android.app.Dialog;
import android.content.ComponentCallbacks2;
import android.content.Intent;
import android.os.Bundle;
import android.text.SpannableStringBuilder;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.FrameLayout;
import androidx.activity.C0035g;
import androidx.activity.v;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.appcompat.widget.Toolbar;
import androidx.lifecycle.C;
import androidx.lifecycle.Z;
import androidx.viewpager.widget.ViewPager;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.android.material.tabs.l;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.managers.h;
import com.quizlet.quizletandroid.ui.base.g;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.quizletandroid.ui.group.GroupActivity;
import com.quizlet.quizletandroid.ui.search.SearchActivity;
import com.quizlet.uicommon.ui.common.dialogs.k;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class b extends AbstractActivityC0055k implements com.quizlet.baseui.interfaces.b, dagger.android.c {
    public C4636c c;
    public g e;
    public Toolbar f;
    public l g;
    public FrameLayout h;
    public k i;
    public final ArrayList d = new ArrayList();
    public final ArrayList j = new ArrayList();

    public Integer B() {
        return null;
    }

    public ViewPager C() {
        return null;
    }

    public abstract String D();

    public final void E(Bundle bundle) {
        if (!(this instanceof dagger.hilt.android.internal.migration.a)) {
            ComponentCallbacks2 application = getApplication();
            if (!(application instanceof dagger.android.c)) {
                throw new RuntimeException(android.support.v4.media.session.a.l(application.getClass().getCanonicalName(), " does not implement ", dagger.android.c.class.getCanonicalName()));
            }
            dagger.android.c cVar = (dagger.android.c) application;
            C4636c c4636cC = cVar.c();
            S6.b(c4636cC, "%s.androidInjector() returned null", cVar.getClass());
            c4636cC.d(this);
        }
        addOnContextAvailableListener(new C0035g(this, 1));
        super.onCreate(bundle);
    }

    public void F() {
        Iterator it2 = this.j.iterator();
        while (it2.hasNext()) {
            ((com.quizlet.baseui.interfaces.a) it2.next()).r();
        }
    }

    public final void G(Dialog dialog) {
        if (isFinishing()) {
            return;
        }
        dialog.show();
        this.d.add(new WeakReference(dialog));
    }

    public boolean H() {
        return !(this instanceof GroupActivity);
    }

    public void I(boolean z) {
        if (!z) {
            k kVar = this.i;
            if (kVar != null) {
                kVar.dismiss();
                this.i = null;
                return;
            }
            return;
        }
        if (this.i == null) {
            this.e.getClass();
            Intrinsics.checkNotNullParameter(this, "context");
            k kVar2 = new k(this, getString(R.string.please_wait));
            this.i = kVar2;
            kVar2.setCancelable(false);
        }
        G(this.i);
    }

    @Override // dagger.android.c
    public final C4636c c() {
        C4636c c4636c = this.c;
        if (c4636c != null) {
            return c4636c;
        }
        Intrinsics.m("androidInjector");
        throw null;
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i2 == 101) {
            setResult(101);
            finish();
        }
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        E(bundle);
        v.a(this);
        g gVar = this.e;
        C lifecycle = getLifecycle();
        gVar.getClass();
        Intrinsics.checkNotNullParameter(lifecycle, "lifecycle");
        lifecycle.a(gVar.c);
        final int i = 0;
        this.e.t.f(this, new Z(this) { // from class: com.quizlet.baseui.base.a
            public final /* synthetic */ b b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object obj) {
                switch (i) {
                    case 0:
                        this.b.F();
                        break;
                    default:
                        com.quizlet.baseui.events.a aVar = (com.quizlet.baseui.events.a) obj;
                        b activity = this.b;
                        aVar.getClass();
                        Intrinsics.checkNotNullParameter(activity, "activity");
                        activity.startActivity(aVar.a);
                        break;
                }
            }
        });
        final int i2 = 1;
        this.e.u.f(this, new Z(this) { // from class: com.quizlet.baseui.base.a
            public final /* synthetic */ b b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object obj) {
                switch (i2) {
                    case 0:
                        this.b.F();
                        break;
                    default:
                        com.quizlet.baseui.events.a aVar = (com.quizlet.baseui.events.a) obj;
                        b activity = this.b;
                        aVar.getClass();
                        Intrinsics.checkNotNullParameter(activity, "activity");
                        activity.startActivity(aVar.a);
                        break;
                }
            }
        });
        Bundle extras = getIntent().getExtras();
        HashMap map = new HashMap();
        if (extras != null) {
            for (String str : extras.keySet()) {
                map.put(str, extras.get(str));
            }
        }
        timber.log.c.a.g("Creating activity %s with extras %s", D(), map.toString());
        int iZ = z();
        if (iZ != 0) {
            setContentView(iZ);
            this.h = (FrameLayout) findViewById(R.id.appbar_header);
            this.g = (l) findViewById(R.id.tablayout);
            this.f = (Toolbar) findViewById(R.id.toolbar);
            setVolumeControlStream(3);
            FrameLayout frameLayout = this.h;
            if (frameLayout == null) {
                return;
            }
            frameLayout.setVisibility(8);
        }
    }

    @Override // android.app.Activity
    public boolean onCreateOptionsMenu(Menu menu) {
        super.onCreateOptionsMenu(menu);
        Integer numB = B();
        if (numB == null) {
            return true;
        }
        getMenuInflater().inflate(numB.intValue(), menu);
        return true;
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public void onDestroy() {
        timber.log.c.a.g("Destroying activity %s", D());
        super.onDestroy();
    }

    @Override // android.app.Activity
    public boolean onOptionsItemSelected(MenuItem menuItem) {
        if (menuItem.getItemId() != 16908332) {
            return super.onOptionsItemSelected(menuItem);
        }
        if (isFinishing()) {
            return true;
        }
        onBackPressed();
        return true;
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public void onPause() {
        timber.log.c.a.g("Pausing activity %s", D());
        this.e.a(this, getResources().getConfiguration().orientation == 2);
        super.onPause();
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        this.e.b(this);
        Toolbar toolbar = this.f;
        if (toolbar != null) {
            try {
                v(toolbar);
            } catch (Throwable th) {
                timber.log.c.a(th);
            }
            if (r() != null) {
                r().u(false);
            }
            r().s(true);
            r().t();
        }
        if (this.g == null) {
            return;
        }
        ViewPager viewPagerC = C();
        if (viewPagerC == null) {
            this.g.setVisibility(8);
        } else {
            this.g.setupWithViewPager(viewPagerC);
        }
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public void onResume() {
        timber.log.c.a.g("Resuming activity %s", D());
        super.onResume();
        this.e.c(this, D(), getResources().getConfiguration().orientation == 2);
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public final boolean onSearchRequested() {
        g gVar = this.e;
        gVar.getClass();
        Intrinsics.checkNotNullParameter(this, "context");
        if (this instanceof SearchActivity) {
            return false;
        }
        Object obj = gVar.o.get();
        Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
        gVar.u.l(new com.quizlet.baseui.events.a((Intent) obj));
        return false;
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public void onStart() {
        timber.log.c.a.g("Starting activity %s", D());
        super.onStart();
        this.e.d(D(), H());
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public void onStop() {
        timber.log.c.a.g("Stopping activity %s", D());
        super.onStop();
        h hVar = this.e.h;
        int i = hVar.a;
        if (i > 0) {
            hVar.a = i - 1;
        }
        if (hVar.a == 0) {
            hVar.b.b(Boolean.FALSE);
        }
        Iterator it2 = this.d.iterator();
        while (it2.hasNext()) {
            Dialog dialog = (Dialog) ((WeakReference) it2.next()).get();
            if (dialog != null && dialog.isShowing()) {
                dialog.dismiss();
            }
        }
        I(false);
    }

    @Override // android.app.Activity
    public final void setTitle(int i) {
        setTitle(getString(i));
    }

    public final void x(io.reactivex.rxjava3.disposables.b disposable) {
        g gVar = this.e;
        gVar.getClass();
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        com.quizlet.baseui.managers.b bVar = gVar.c;
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        Object value = bVar.d.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).b(disposable);
    }

    public final void y(io.reactivex.rxjava3.disposables.b disposable) {
        g gVar = this.e;
        gVar.getClass();
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        com.quizlet.baseui.managers.b bVar = gVar.c;
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        Object value = bVar.c.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).b(disposable);
    }

    public abstract int z();

    @Override // android.app.Activity
    public final void setTitle(CharSequence charSequence) {
        SpannableStringBuilder spannableStringBuilder;
        if (r() != null) {
            r().u(true);
        }
        this.e.getClass();
        Intrinsics.checkNotNullParameter(this, "context");
        if (charSequence != null) {
            spannableStringBuilder = new SpannableStringBuilder(charSequence);
            AbstractC3161h6.g(spannableStringBuilder, this, com.quizlet.ui.resources.designsystem.generated.a.d);
        } else {
            spannableStringBuilder = null;
        }
        super.setTitle(spannableStringBuilder);
    }
}
