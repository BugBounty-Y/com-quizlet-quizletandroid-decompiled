package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import androidx.activity.v;
import androidx.appcompat.widget.SearchView;
import androidx.appcompat.widget.Toolbar;
import androidx.lifecycle.y0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4602f;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class EditSetLanguageSelectionActivity extends com.quizlet.baseui.base.f implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a, com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.c {
    public static final /* synthetic */ int z = 0;
    public RecyclerView l;
    public com.quizlet.quizletandroid.util.f m;
    public com.quizlet.infra.legacysyncengine.managers.d n;
    public com.quizlet.quizletandroid.ui.setcreation.adapters.a o;
    public ArrayList p;
    public ArrayList q;
    public boolean r;
    public String s;
    public com.quizlet.quizletandroid.ui.setcreation.adapters.c t;
    public SearchView u;
    public com.quizlet.login.authentication.login.a v;
    public volatile dagger.hilt.android.internal.managers.b w;
    public final Object x = new Object();
    public boolean y = false;

    public EditSetLanguageSelectionActivity() {
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i(this, 15));
    }

    public static Intent Q(Context context, String str, boolean z2) {
        Intent intent = new Intent(context, (Class<?>) EditSetLanguageSelectionActivity.class);
        intent.putExtra("editSetLanguageActivityIsWordLanguage", z2);
        intent.putExtra("editSetLanguageActivityCurrentLanguage", str);
        return intent;
    }

    @Override // com.quizlet.baseui.base.b
    public final Integer B() {
        return Integer.valueOf(R.menu.edit_set_language_selection_menu);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return "EditSetLanguageSelectionActivity";
    }

    @Override // com.quizlet.baseui.base.f
    public final com.google.android.material.tabs.l L() {
        return (QTabLayout) ((C4602f) this.k).b.c;
    }

    @Override // com.quizlet.baseui.base.f
    public final Toolbar M() {
        return (Toolbar) ((C4602f) this.k).b.f;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        return C4602f.a(getLayoutInflater());
    }

    public final void O(Locale locale, ArrayList arrayList) {
        int iIndexOf;
        if (locale == null || locale.getLanguage().isEmpty()) {
            return;
        }
        String language = locale.getLanguage();
        if (org.apache.commons.lang3.e.b(this.m.d(language)) || (iIndexOf = arrayList.indexOf(language)) == 0) {
            return;
        }
        if (iIndexOf > -1) {
            arrayList.remove(iIndexOf);
        }
        arrayList.add(0, language);
    }

    public final dagger.hilt.android.internal.managers.b P() {
        if (this.w == null) {
            synchronized (this.x) {
                try {
                    if (this.w == null) {
                        this.w = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.w;
    }

    public final void R(Bundle bundle) {
        super.onCreate(bundle);
        v.a(this);
        AbstractC3188k6.a(((C4602f) this.k).a);
        Bundle extras = getIntent().getExtras();
        if (bundle == null) {
            bundle = extras;
        }
        this.r = bundle.getBoolean("editSetLanguageActivityIsWordLanguage");
        this.s = bundle.getString("editSetLanguageActivityCurrentLanguage");
        this.p = new ArrayList();
        this.q = new ArrayList();
        com.quizlet.quizletandroid.ui.setcreation.adapters.a aVar = this.o;
        com.quizlet.quizletandroid.util.f languageUtil = this.m;
        String str = this.s;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(this, "provider");
        Intrinsics.checkNotNullParameter(languageUtil, "languageUtil");
        com.quizlet.quizletandroid.ui.setcreation.adapters.c cVar = new com.quizlet.quizletandroid.ui.setcreation.adapters.c(this, languageUtil, str);
        this.t = cVar;
        RecyclerView recyclerView = ((C4602f) this.k).c;
        this.l = recyclerView;
        recyclerView.setAdapter(cVar);
        this.l.setLayoutManager(new LinearLayoutManager(this));
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

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        setResult(1234);
        com.bumptech.glide.c.C(this.u, false);
        super.onBackPressed();
    }

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        R(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = P().b();
            this.v = aVarB;
            if (aVarB.l()) {
                this.v.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // com.quizlet.baseui.base.b, android.app.Activity
    public final boolean onCreateOptionsMenu(Menu menu) {
        super.onCreateOptionsMenu(menu);
        MenuItem menuItemFindItem = menu.findItem(R.id.menu_toolbar_search);
        if (menuItemFindItem != null) {
            SearchView searchView = (SearchView) menuItemFindItem.getActionView();
            this.u = searchView;
            if (searchView != null) {
                searchView.setOnQueryTextListener(new com.quizlet.data.repository.explanations.myexplanations.a(27, this, menuItemFindItem));
            }
        }
        return true;
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.v;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        setTitle(this.r ? R.string.term_language : R.string.definition_language);
        ArrayList arrayList = new ArrayList(((Map) this.m.b.getValue()).keySet());
        HashMap map = new HashMap();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            map.put(this.m.d(str), str);
        }
        ArrayList arrayList2 = new ArrayList(map.keySet());
        Collections.sort(arrayList2);
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            this.q.add((String) map.get((String) it3.next()));
        }
        this.m.getClass();
        ArrayList arrayList3 = new ArrayList(com.quizlet.generated.sharedconfig.c.b);
        DBUser dBUser = this.n.r;
        if (dBUser != null) {
            if (dBUser.getMobileLocale() != null) {
                O(Locale.forLanguageTag(dBUser.getMobileLocale()), arrayList3);
            }
            if (dBUser.getUserLocalePreference() != null) {
                O(Locale.forLanguageTag(dBUser.getUserLocalePreference()), arrayList3);
            }
        }
        this.p.addAll(arrayList3);
        this.t.notifyDataSetChanged();
    }

    @Override // androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        bundle.putBoolean("editSetLanguageActivityIsWordLanguage", this.r);
        bundle.putString("editSetLanguageActivityCurrentLanguage", this.s);
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.y;
    }
}
