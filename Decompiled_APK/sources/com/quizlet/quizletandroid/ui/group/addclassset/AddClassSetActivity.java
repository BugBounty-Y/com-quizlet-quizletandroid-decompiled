package com.quizlet.quizletandroid.ui.group.addclassset;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.content.Intent;
import android.content.res.Resources;
import android.database.DataSetObserver;
import android.os.Bundle;
import android.util.SparseArray;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.activity.v;
import androidx.appcompat.widget.Toolbar;
import androidx.compose.foundation.text.input.internal.u;
import androidx.lifecycle.y0;
import androidx.viewpager.widget.ViewPager;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.tabs.l;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.features.infra.legacyadapter.databinding.h;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4599c;
import com.quizlet.quizletandroid.ui.common.views.ToggleSwipeableViewPager;
import com.quizlet.quizletandroid.ui.group.i;
import io.reactivex.rxjava3.internal.operators.observable.B;
import io.reactivex.rxjava3.internal.operators.observable.r;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes3.dex */
public class AddClassSetActivity extends com.quizlet.baseui.base.f implements d, dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final /* synthetic */ int w = 0;
    public com.quizlet.login.authentication.login.a l;
    public volatile dagger.hilt.android.internal.managers.b m;
    public final Object n = new Object();
    public boolean o = false;
    public a p;
    public com.quizlet.infra.legacysyncengine.net.f q;
    public com.quizlet.infra.legacysyncengine.managers.d r;
    public u s;
    public com.quizlet.features.notes.a t;
    public List u;
    public Long v;

    public AddClassSetActivity() {
        addOnContextAvailableListener(new i(this, 1));
    }

    @Override // com.quizlet.baseui.base.b
    public final Integer B() {
        return Integer.valueOf(R.menu.add_class_set_menu);
    }

    @Override // com.quizlet.baseui.base.b
    public final ViewPager C() throws Resources.NotFoundException {
        a aVar = new a(this, getSupportFragmentManager());
        this.p = aVar;
        ((C4599c) this.k).b.setAdapter(aVar);
        ToggleSwipeableViewPager toggleSwipeableViewPager = ((C4599c) this.k).b;
        this.p.getClass();
        toggleSwipeableViewPager.setOffscreenPageLimit(2);
        return ((C4599c) this.k).b;
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return "AddClassSetActivity";
    }

    @Override // com.quizlet.baseui.base.f
    public final FrameLayout J() {
        return (FrameLayout) ((C4599c) this.k).c.d;
    }

    @Override // com.quizlet.baseui.base.f
    public final l L() {
        return (QTabLayout) ((C4599c) this.k).c.c;
    }

    @Override // com.quizlet.baseui.base.f
    public final Toolbar M() {
        return (Toolbar) ((C4599c) this.k).c.f;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_add_class_set, (ViewGroup) null, false);
        int i = R.id.add_set_to_class_viewpager;
        ToggleSwipeableViewPager toggleSwipeableViewPager = (ToggleSwipeableViewPager) AbstractC3375o2.c(R.id.add_set_to_class_viewpager, viewInflate);
        if (toggleSwipeableViewPager != null) {
            i = R.id.layoutAppbar;
            View viewC = AbstractC3375o2.c(R.id.layoutAppbar, viewInflate);
            if (viewC != null) {
                return new C4599c((LinearLayout) viewInflate, toggleSwipeableViewPager, h.a(viewC));
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final dagger.hilt.android.internal.managers.b O() {
        if (this.m == null) {
            synchronized (this.n) {
                try {
                    if (this.m == null) {
                        this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.m;
    }

    public final void P(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = O().b();
            this.l = aVarB;
            if (aVarB.l()) {
                this.l.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    public final void Q() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.l;
        if (aVar != null) {
            aVar.b = null;
        }
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

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        P(bundle);
        v.a(this);
        AbstractC3188k6.a(((C4599c) this.k).a);
        Intent intent = getIntent();
        Bundle extras = intent.getExtras();
        if (extras == null || !extras.containsKey("current_class_id")) {
            throw new IllegalStateException("Tried to launch AddClassSetActivity without appropriate extras!");
        }
        this.v = Long.valueOf(intent.getLongExtra("current_class_id", 0L));
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() throws Resources.NotFoundException {
        ((SparseArray) this.p.k).clear();
        a aVar = this.p;
        synchronized (aVar) {
            try {
                DataSetObserver dataSetObserver = aVar.b;
                if (dataSetObserver != null) {
                    dataSetObserver.onChanged();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        aVar.a.notifyChanged();
        ((C4599c) this.k).b.setAdapter(this.p);
        this.p = null;
        ((C4599c) this.k).b.setAdapter(null);
        Q();
    }

    @Override // com.quizlet.baseui.base.b, android.app.Activity
    public final boolean onOptionsItemSelected(MenuItem menuItem) {
        if (menuItem.getItemId() != R.id.menu_add_class_set_complete) {
            return super.onOptionsItemSelected(menuItem);
        }
        this.t.a.b(null, "add_class_set_complete");
        HashSet hashSet = new HashSet();
        for (int i = 0; i < 3; i++) {
            hashSet.addAll(((AddToClassSetListFragment) ((BaseFragment) ((SparseArray) this.p.k).get(i))).v.a);
        }
        ArrayList arrayList = new ArrayList();
        for (DBGroupSet dBGroupSet : this.u) {
            if (!hashSet.contains(Long.valueOf(dBGroupSet.getSetId()))) {
                dBGroupSet.setDeleted(true);
                arrayList.add(dBGroupSet);
            }
        }
        Iterator it2 = this.u.iterator();
        while (it2.hasNext()) {
            Long lValueOf = Long.valueOf(((DBGroupSet) it2.next()).getSetId());
            if (hashSet.contains(lValueOf)) {
                hashSet.remove(lValueOf);
            }
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it3 = hashSet.iterator();
        while (it3.hasNext()) {
            arrayList2.add(DBGroupSet.createNewInstance(this.v.longValue(), ((Long) it3.next()).longValue(), this.r.e.getPersonId()));
        }
        int size = arrayList2.size() - arrayList.size();
        com.quizlet.features.notes.a aVar = this.t;
        aVar.a.b(Integer.valueOf(size), "add_class_set_net_change");
        r rVarG = io.reactivex.rxjava3.core.i.g(this.q.b(arrayList), this.q.b(arrayList2));
        com.quizlet.quizletandroid.ui.common.adapter.presenter.a aVar2 = new com.quizlet.quizletandroid.ui.common.adapter.presenter.a(this, arrayList, arrayList2, 1);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        new B(rVarG, gVar, gVar, aVar2, io.reactivex.rxjava3.internal.functions.d.c).t();
        return true;
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        setTitle(R.string.add_class_set_title);
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.o;
    }
}
