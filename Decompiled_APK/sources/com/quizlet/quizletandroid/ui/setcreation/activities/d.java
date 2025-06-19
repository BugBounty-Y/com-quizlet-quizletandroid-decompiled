package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.content.Intent;
import android.content.res.Resources;
import android.os.Build;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import android.widget.Toast;
import androidx.appcompat.widget.Toolbar;
import androidx.compose.ui.platform.ComposeView;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.lifecycle.Y;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.model.TermContentSuggestions;
import com.quizlet.data.model.G0;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.generated.enums.O1;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4600d;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setcreation.managers.NewCardFABBehavior;
import com.quizlet.quizletandroid.ui.setcreation.managers.v;
import com.quizlet.uicommon.ui.common.dialogs.e;
import io.reactivex.rxjava3.subjects.r;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class d extends com.quizlet.baseui.base.f implements com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b, com.quizlet.quizletandroid.ui.setcreation.managers.g {
    public static final /* synthetic */ int H = 0;
    public com.quizlet.quizletandroid.ui.setcreation.managers.k A;
    public EditSetFragment B;
    public RelativeLayout C;
    public FloatingActionButton D;
    public CoordinatorLayout E;
    public ArrayList G;
    public com.quizlet.quizletandroid.sessionhelpers.a m;
    public com.quizlet.db.a n;
    public UserInfoCache o;
    public DatabaseHelper p;
    public com.quizlet.quizletandroid.util.f q;
    public com.quizlet.infra.legacysyncengine.net.f r;
    public v s;
    public com.quizlet.infra.legacysyncengine.managers.d t;
    public IQuizletApiClient u;
    public EventLogger v;
    public io.reactivex.rxjava3.core.o w;
    public io.reactivex.rxjava3.core.o x;
    public com.quizlet.quizletandroid.ui.setcreation.managers.i y;
    public com.quizlet.offline.managers.b z;
    public final Y l = new Y(Boolean.FALSE);
    public boolean F = true;

    @Override // com.quizlet.baseui.base.b
    public final Integer B() {
        return Integer.valueOf(R.menu.edit_set_menu);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return "EditSetActivity";
    }

    @Override // com.quizlet.baseui.base.f
    public final FrameLayout J() {
        return (FrameLayout) ((C4600d) this.k).c.d;
    }

    @Override // com.quizlet.baseui.base.f
    public final com.google.android.material.tabs.l L() {
        return (QTabLayout) ((C4600d) this.k).c.c;
    }

    @Override // com.quizlet.baseui.base.f
    public final Toolbar M() {
        return (Toolbar) ((C4600d) this.k).c.f;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_edit_set, (ViewGroup) null, false);
        int i = R.id.add_card_fab;
        FloatingActionButton floatingActionButton = (FloatingActionButton) AbstractC3375o2.c(R.id.add_card_fab, viewInflate);
        if (floatingActionButton != null) {
            i = R.id.appbar;
            View viewC = AbstractC3375o2.c(R.id.appbar, viewInflate);
            if (viewC != null) {
                com.quizlet.features.infra.legacyadapter.databinding.h hVarA = com.quizlet.features.infra.legacyadapter.databinding.h.a(viewC);
                i = R.id.compose_view;
                ComposeView composeView = (ComposeView) AbstractC3375o2.c(R.id.compose_view, viewInflate);
                if (composeView != null) {
                    i = R.id.edit_set_coordinatorLayout;
                    CoordinatorLayout coordinatorLayout = (CoordinatorLayout) AbstractC3375o2.c(R.id.edit_set_coordinatorLayout, viewInflate);
                    if (coordinatorLayout != null) {
                        i = R.id.edit_set_fragment_container;
                        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.edit_set_fragment_container, viewInflate);
                        if (frameLayout != null) {
                            i = R.id.edit_set_spinner;
                            RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.edit_set_spinner, viewInflate);
                            if (relativeLayout != null) {
                                FrameLayout frameLayout2 = (FrameLayout) viewInflate;
                                return new C4600d(frameLayout2, floatingActionButton, hVarA, composeView, coordinatorLayout, frameLayout, relativeLayout, frameLayout2);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void O(TermContentSuggestions termContentSuggestions) {
        EditSetFragment editSetFragment = this.B;
        if (editSetFragment != null) {
            com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = editSetFragment.C;
            fVar.getClass();
            TermContentSuggestions.Parameters parameters = termContentSuggestions.parameters;
            int iH = (parameters == null ? -1 : fVar.h(Long.parseLong(parameters.localTermId))) + 1;
            DBTerm dBTermJ = fVar.j(iH);
            if (dBTermJ == null) {
                return;
            }
            fVar.i.g(dBTermJ.getLocalId(), termContentSuggestions);
            if (fVar.k() != null) {
                fVar.k().f(dBTermJ, false, null, termContentSuggestions);
            }
            fVar.notifyItemChanged(iH, 300);
            com.quizlet.quizletandroid.ui.setcreation.adapters.f.l(false, termContentSuggestions);
        }
    }

    public final void P(TermContentSuggestions termContentSuggestions) {
        EditSetFragment editSetFragment = this.B;
        if (editSetFragment != null) {
            com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = editSetFragment.C;
            fVar.getClass();
            TermContentSuggestions.Parameters parameters = termContentSuggestions.parameters;
            int iH = (parameters == null ? -1 : fVar.h(Long.parseLong(parameters.localTermId))) + 1;
            DBTerm dBTermJ = fVar.j(iH);
            if (dBTermJ == null) {
                return;
            }
            fVar.h.g(dBTermJ.getLocalId(), termContentSuggestions);
            if (fVar.k() != null) {
                fVar.k().f(dBTermJ, true, null, termContentSuggestions);
            }
            fVar.notifyItemChanged(iH, 300);
            com.quizlet.quizletandroid.ui.setcreation.adapters.f.l(true, termContentSuggestions);
        }
    }

    public final void Q(long j, String str, String str2) {
        EditSetFragment editSetFragment = this.B;
        if (editSetFragment != null) {
            com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = editSetFragment.C;
            fVar.i.h(j);
            int iH = fVar.h(j);
            fVar.notifyItemChanged(iH != -1 ? iH + 1 : -1, 300);
            timber.log.c.a.g("No suggestions for definition\t(request may or may not have been made) : %d, word %s w/ prefix '%s'", Long.valueOf(j), str, str2);
        }
    }

    public final void R(long j, String str) {
        EditSetFragment editSetFragment = this.B;
        if (editSetFragment != null) {
            com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = editSetFragment.C;
            fVar.h.h(j);
            int iH = fVar.h(j);
            fVar.notifyItemChanged(iH != -1 ? iH + 1 : -1, 300);
            timber.log.c.a.g("No suggestions for word\t(request may or may not have been made) : %d, w/ prefix '%s'", Long.valueOf(j), str);
        }
    }

    public final boolean S() {
        ArrayList arrayList;
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = this.B.A;
        List listUnmodifiableList = null;
        if (fVar != null && (arrayList = fVar.p) != null) {
            listUnmodifiableList = Collections.unmodifiableList(arrayList);
        }
        this.y.e(this.r);
        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = this.y;
        boolean z = iVar.e.a;
        if (z) {
            iVar.o.i(new com.quizlet.infra.legacysyncengine.managers.a(4, iVar, listUnmodifiableList), new com.quizlet.billing.subscriptions.c(2));
        }
        return z;
    }

    public final void T(O1 o1, List list) {
        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = this.y;
        DBStudySet dBStudySet = iVar.m;
        if (iVar.b(o1) || dBStudySet == null) {
            return;
        }
        String languageCode = dBStudySet.getLanguageCode(o1);
        if (languageCode == null || languageCode.isEmpty()) {
            if (this.A == null) {
                com.quizlet.quizletandroid.ui.setcreation.managers.k kVar = new com.quizlet.quizletandroid.ui.setcreation.managers.k(this.u, this.w, this.x, this.t.e.getPersonId(), dBStudySet.getId());
                this.A = kVar;
                kVar.i = this;
            }
            com.quizlet.quizletandroid.ui.setcreation.managers.k kVar2 = this.A;
            if (kVar2.i == null) {
                throw new IllegalStateException("setListener must be called before suggest");
            }
            if (o1 == O1.WORD) {
                kVar2.g.b(list);
            } else if (o1 == O1.DEFINITION) {
                kVar2.h.b(list);
            }
        }
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.managers.g
    public final void b() {
        this.m.k(this.v, "delete");
        Intrinsics.checkNotNullParameter(this, "context");
        Intent intentA = D4.a(this, null);
        intentA.setFlags(335544320);
        startActivity(intentA);
        finish();
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.managers.g
    public final void f(com.quizlet.infra.legacysyncengine.net.request.i iVar) {
        Toast.makeText(this, iVar.a(this), 1).show();
        timber.log.c.a.d("The user was shown the following error encountered during a save and publish : %s", iVar.a(this));
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.managers.g
    public final void j(int i, boolean z) {
        EditSetFragment editSetFragment = this.B;
        if (editSetFragment != null) {
            com.quizlet.uicommon.ui.common.dialogs.l lVarP = com.quizlet.uicommon.ui.common.dialogs.l.P(0, i, R.string.OK);
            Intrinsics.checkNotNullExpressionValue(lVarP, "newInstance(...)");
            if (z) {
                lVarP.setTargetFragment(editSetFragment, 100);
            }
            lVarP.O(editSetFragment.requireFragmentManager(), EditSetFragment.J);
        }
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.managers.g
    public final void k(boolean z) {
        Intent intentA;
        if (this.B != null) {
            this.C.setVisibility(8);
            this.D.setEnabled(true);
        }
        if (z) {
            if (this.y.s) {
                this.v.I("create_set");
            }
            this.m.k(this.v, "publish");
            AddMaterialFolderData addMaterialFolderData = (AddMaterialFolderData) getIntent().getParcelableExtra("addMaterialFolderData");
            if (getIntent().getBooleanExtra("isFromHome", false)) {
                long setId = this.y.m.getSetId();
                Boolean boolValueOf = Boolean.valueOf(this.y.s);
                com.quizlet.features.setpage.e eVar = SetPageActivity.h1;
                Intrinsics.checkNotNullParameter(this, "context");
                intentA = com.quizlet.features.setpage.e.b(eVar, this, setId, null, null, boolValueOf, null, false, null, 224);
                intentA.putExtra("isFromHome", true);
            } else if (addMaterialFolderData != null) {
                long setId2 = this.y.m.getSetId();
                com.quizlet.features.setpage.e eVar2 = SetPageActivity.h1;
                Intrinsics.checkNotNullParameter(this, "context");
                Intrinsics.checkNotNullParameter(addMaterialFolderData, "addMaterialFolderData");
                intentA = com.quizlet.features.setpage.e.b(eVar2, this, setId2, null, null, null, null, false, null, 252);
                intentA.putExtra("addMaterialFolderData", addMaterialFolderData);
                setResult(-1);
            } else {
                intentA = SetPageActivity.h1.a(this, this.y.m.getSetId(), this.y.s);
            }
            if (!getIntent().getBooleanExtra("shouldFinishWithoutNewActivity", false)) {
                intentA.addFlags(67108864);
                startActivity(intentA);
            }
            finish();
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        String stringExtra;
        boolean booleanExtra;
        super.onActivityResult(i, i2, intent);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
        if (i == 4000 || i == 3000) {
            if (intent != null && i2 == 4321 && (stringExtra = intent.getStringExtra("editSetLanguageCodeResult")) != null) {
                this.m.e("language");
                com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = this.y;
                if (iVar.m == null) {
                    x(iVar.o.i(new c(this, i, stringExtra, 0), gVar));
                } else {
                    String strA = this.q.a(stringExtra);
                    if (org.apache.commons.lang3.e.b(strA)) {
                        timber.log.c.b(new IllegalStateException("No translated language code could be found for ".concat(stringExtra)));
                    } else if (i == 4000) {
                        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar2 = this.y;
                        O1 o1 = O1.DEFINITION;
                        iVar2.f(o1, stringExtra, false);
                        this.B.g0(o1, strA);
                    } else if (i == 3000) {
                        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar3 = this.y;
                        O1 o12 = O1.WORD;
                        iVar3.f(o12, stringExtra, false);
                        this.B.g0(o12, strA);
                    }
                }
            }
        } else if (i == 2000) {
            this.m.e("tab_terms");
            if (i2 == 100) {
                b();
            }
            if (intent != null && intent.hasExtra("autoSuggest") && this.F != (booleanExtra = intent.getBooleanExtra("autoSuggest", this.F))) {
                this.F = booleanExtra;
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = this.B.A;
                if (fVar != null) {
                    fVar.v = booleanExtra;
                    fVar.notifyDataSetChanged();
                }
            }
        } else if (i == 1000 && i2 == 1001) {
            x(this.y.q.i(new com.quizlet.infra.legacysyncengine.managers.a(3, this, intent), gVar));
        }
        this.m.c(i, i2, intent);
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        if (this.B == null) {
            return;
        }
        String str = "empty_discard";
        if (!S()) {
            com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = this.y;
            if (iVar.l) {
                this.m.k(this.v, "empty_discard");
                e.a aVar = new e.a(this);
                aVar.c(this.y.l ? R.string.cancel_copy_set_confirmation : R.string.delete_set_confirmation);
                aVar.e(R.string.yes_dialog_button, new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 13));
                aVar.d(R.string.no_dialog_button, new com.quizlet.infra.legacysyncengine.models.serializers.a(26));
                aVar.g();
                return;
            }
            DBStudySet dBStudySet = iVar.m;
            str = (dBStudySet == null || !dBStudySet.getIsCreated()) ? "navigate" : "save";
        }
        this.m.k(this.v, str);
        super.onBackPressed();
    }

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        int i = 3;
        super.onCreate(bundle);
        androidx.activity.v.a(this);
        C4600d c4600d = (C4600d) this.k;
        Resources resources = getResources();
        Intrinsics.checkNotNullParameter(c4600d, "<this>");
        Intrinsics.checkNotNullParameter(resources, "resources");
        int dimension = (int) resources.getDimension(R.dimen.quizlet_edge_margin);
        FrameLayout frameLayout = c4600d.a;
        com.google.android.material.sidesheet.b bVar = new com.google.android.material.sidesheet.b(c4600d, dimension);
        WeakHashMap weakHashMap = V.a;
        L.m(frameLayout, bVar);
        C4600d c4600d2 = (C4600d) this.k;
        this.C = c4600d2.g;
        FloatingActionButton floatingActionButton = c4600d2.b;
        this.D = floatingActionButton;
        floatingActionButton.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 13));
        this.E = ((C4600d) this.k).e;
        Intent intent = getIntent();
        ArrayList arrayListA = Build.VERSION.SDK_INT >= 34 ? androidx.core.content.e.a(intent, "predictionFromNotes", G0.class) : intent.getParcelableArrayListExtra("predictionFromNotes");
        this.G = arrayListA;
        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = this.y;
        iVar.t = arrayListA;
        iVar.p = new WeakReference(this);
        getLifecycle().a(this.y);
        this.y.c(bundle);
        r rVar = this.y.o;
        b bVar2 = new b(this, 2);
        rVar.getClass();
        new io.reactivex.rxjava3.internal.operators.single.d(rVar, bVar2, 1).i(new b(this, i), io.reactivex.rxjava3.internal.functions.d.e);
        this.m = new com.quizlet.quizletandroid.sessionhelpers.a("NEW", getIntent());
        getLifecycle().a(this.m);
        this.m.h(bundle);
        getSupportFragmentManager().b(new com.quizlet.explanations.textbook.ui.b(this, i));
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    /* JADX WARN: Type inference failed for: r1v1, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        v vVar = this.s;
        vVar.g = null;
        vVar.h.dispose();
        vVar.i.dispose();
    }

    @Override // com.quizlet.baseui.base.b, android.app.Activity
    public final boolean onOptionsItemSelected(MenuItem menuItem) {
        int itemId = menuItem.getItemId();
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
        if (itemId == R.id.menu_set_complete) {
            if (this.B == null) {
                return true;
            }
            x(io.reactivex.rxjava3.core.p.f(Boolean.TRUE).i(new b(this, 0), gVar));
            return true;
        }
        if (itemId != R.id.menu_settings) {
            return super.onOptionsItemSelected(menuItem);
        }
        x(this.y.o.i(new b(this, 1), gVar));
        return true;
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        this.s.g = this;
    }

    @Override // android.app.Activity
    public final boolean onPrepareOptionsMenu(Menu menu) {
        super.onPrepareOptionsMenu(menu);
        androidx.work.impl.model.f.b(menu, R.id.menu_set_complete, this.o.b());
        return true;
    }

    @Override // androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = this.y;
        bundle.putLong("editSetActivityId", iVar.k.longValue());
        bundle.putBoolean("editSetActivityIsCopySetFlow", iVar.l);
        bundle.putParcelable("editSessionTrackerKey", this.m.a);
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() {
        super.onStart();
        boolean z = false;
        int i = this.n.a.getInt("new_edit_set_onboarding_toast_count", 0);
        if (i < 5) {
            Toast.makeText(this, R.string.edit_set_new_features_toast_msg, 0).show();
            this.n.a.edit().putInt("new_edit_set_onboarding_toast_count", i + 1).apply();
        }
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        EditSetFragment editSetFragment = (EditSetFragment) supportFragmentManager.D(R.id.edit_set_fragment_container);
        if (editSetFragment == null) {
            C1121a c1121a = new C1121a(supportFragmentManager);
            ArrayList arrayList = this.G;
            if (arrayList != null && !arrayList.isEmpty()) {
                z = true;
            }
            EditSetFragment editSetFragment2 = new EditSetFragment();
            editSetFragment2.setArguments(AbstractC3206m6.a(new Pair("isInSetFromNotesMode", Boolean.valueOf(z))));
            this.B = editSetFragment2;
            c1121a.l(R.id.edit_set_fragment_container, editSetFragment2, EditSetFragment.J);
            c1121a.g();
        } else {
            this.B = editSetFragment;
        }
        androidx.coordinatorlayout.widget.e eVar = (androidx.coordinatorlayout.widget.e) this.D.getLayoutParams();
        EditSetFragment editSetFragment3 = this.B;
        NewCardFABBehavior newCardFABBehavior = new NewCardFABBehavior();
        newCardFABBehavior.b = R.id.edit_set_fragment_container;
        newCardFABBehavior.c = new com.quizlet.login.authentication.login.a(editSetFragment3, 10);
        eVar.b(newCardFABBehavior);
        this.D.requestLayout();
    }
}
