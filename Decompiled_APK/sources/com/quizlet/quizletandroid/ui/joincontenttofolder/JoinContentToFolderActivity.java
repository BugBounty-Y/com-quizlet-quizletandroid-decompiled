package com.quizlet.quizletandroid.ui.joincontenttofolder;

import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import androidx.activity.v;
import androidx.compose.ui.node.B;
import androidx.compose.ui.platform.ComposeView;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.lifecycle.Y;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.quizlet.data.repository.classfolder.c;
import com.quizlet.data.repository.classfolder.e;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.features.setpage.viewmodel.C4430d;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.ads.G;
import io.reactivex.rxjava3.internal.operators.flowable.b;
import io.reactivex.rxjava3.subjects.r;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class JoinContentToFolderActivity extends com.quizlet.features.emailconfirmation.ui.activities.l {
    public static final String r;
    public static final int s;
    public static final int t;
    public com.onetrust.otpublishers.headless.UI.viewmodel.c p;
    public k q;

    static {
        Intrinsics.checkNotNullExpressionValue("JoinContentToFolderActivity", "getSimpleName(...)");
        r = "JoinContentToFolderActivity";
        s = R.layout.activity_add_set_to_class;
        t = R.menu.add_set_to_class_menu;
    }

    public JoinContentToFolderActivity() {
        super(5);
        new Y(Boolean.FALSE);
    }

    @Override // com.quizlet.baseui.base.b
    public final Integer B() {
        return Integer.valueOf(t);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return r;
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        setResult(0);
        super.onBackPressed();
    }

    @Override // com.quizlet.features.emailconfirmation.ui.activities.l, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        List studySetIds;
        super.onCreate(bundle);
        v.b(this, null, 3);
        View viewFindViewById = findViewById(R.id.addClassSetContainer);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "findViewById(...)");
        AbstractC3188k6.a(viewFindViewById);
        com.onetrust.otpublishers.headless.UI.viewmodel.c cVar = this.p;
        if (cVar == null) {
            Intrinsics.m("viewModelFactory");
            throw null;
        }
        this.q = (k) D6.f(this, cVar).a(k.class);
        View viewFindViewById2 = findViewById(R.id.composeView);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById2, "findViewById(...)");
        ComposeView composeView = (ComposeView) viewFindViewById2;
        k kVar = this.q;
        if (kVar == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        AbstractC3107b6.h(composeView, kVar.t, new com.quizlet.login.magiclink.ui.e(this, 15), R.string.offline_dialog_title, R.string.offline_dialog_description);
        long[] longArrayExtra = getIntent().getLongArrayExtra("setIds");
        if (longArrayExtra == null || (studySetIds = C4933y.O(longArrayExtra)) == null) {
            studySetIds = K.a;
        }
        long longExtra = getIntent().getLongExtra(DBGroupMembershipFields.Names.CLASS_ID, 0L);
        if (longExtra != 0) {
            k kVar2 = this.q;
            if (kVar2 == null) {
                Intrinsics.m("viewModel");
                throw null;
            }
            timber.log.c.a.g("ViewModel initialization started", new Object[0]);
            kVar2.m = Long.valueOf(longExtra);
            kVar2.k = kVar2.h.getPersonId();
            kVar2.D();
            return;
        }
        k kVar3 = this.q;
        if (kVar3 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        Intrinsics.checkNotNullParameter(studySetIds, "studySetIds");
        timber.log.c.a.g("ViewModel initialization started", new Object[0]);
        kVar3.l = studySetIds;
        kVar3.k = kVar3.h.getPersonId();
        kVar3.D();
    }

    @Override // com.quizlet.baseui.base.b, android.app.Activity
    public final boolean onOptionsItemSelected(MenuItem item) {
        Intrinsics.checkNotNullParameter(item, "item");
        if (item.getItemId() != R.id.menu_add_set_complete) {
            return super.onOptionsItemSelected(item);
        }
        k kVar = this.q;
        if (kVar == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        Y y = kVar.r;
        if (!Intrinsics.b(y.d(), e.a) && !(y.d() instanceof d)) {
            Object objD = y.d();
            c cVar = c.b;
            if (!Intrinsics.b(objD, cVar)) {
                Long l = kVar.m;
                if (l == null && !((com.quizlet.offline.managers.i) kVar.j).i) {
                    kVar.t.j(Boolean.TRUE);
                    return true;
                }
                boolean z = l != null;
                r stopToken = kVar.q;
                if (z) {
                    if (l == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    final long jLongValue = l.longValue();
                    y.l(cVar);
                    timber.log.c.a.g("Creating ClassFolders to reflect selections...", new Object[0]);
                    final ArrayList originalFolderIds = kVar.o;
                    if (originalFolderIds == null) {
                        Intrinsics.m("initialClassFolders");
                        throw null;
                    }
                    LinkedHashSet linkedHashSet = kVar.s;
                    if (linkedHashSet == null) {
                        Intrinsics.m("selectedFolderIds");
                        throw null;
                    }
                    final List newFolderIds = CollectionsKt.w0(linkedHashSet);
                    final androidx.work.impl.model.l lVar = kVar.g;
                    lVar.getClass();
                    Intrinsics.checkNotNullParameter(originalFolderIds, "originalFolderIds");
                    Intrinsics.checkNotNullParameter(newFolderIds, "newFolderIds");
                    Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                    io.reactivex.rxjava3.internal.operators.completable.c cVar2 = new io.reactivex.rxjava3.internal.operators.completable.c(((androidx.work.impl.model.c) lVar.c).c(stopToken, new Function0() { // from class: com.quizlet.data.interactor.classfolder.a
                        @Override // kotlin.jvm.functions.Function0
                        public final Object invoke() {
                            e eVar = (e) lVar.b;
                            ArrayList originalFolderIds2 = originalFolderIds;
                            Intrinsics.checkNotNullParameter(originalFolderIds2, "originalFolderIds");
                            List newFolderIds2 = newFolderIds;
                            Intrinsics.checkNotNullParameter(newFolderIds2, "newFolderIds");
                            b bVar = new b(new c(eVar, newFolderIds2, originalFolderIds2, jLongValue), 4);
                            Intrinsics.checkNotNullExpressionValue(bVar, "defer(...)");
                            return bVar;
                        }
                    }), 6);
                    Intrinsics.checkNotNullExpressionValue(cVar2, "ignoreElement(...)");
                    io.reactivex.rxjava3.internal.observers.e eVarF = cVar2.f(new com.quizlet.features.setpage.terms.a(kVar, jLongValue, 1), new h(kVar, 0));
                    Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(...)");
                    Intrinsics.checkNotNullParameter(eVarF, "<this>");
                    kVar.A(eVarF);
                    return true;
                }
                List setIds = kVar.l;
                if (setIds == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                y.l(cVar);
                timber.log.c.a.g("Creating FolderSets to reflect selections...", new Object[0]);
                List originalFolderIds2 = kVar.n;
                if (originalFolderIds2 == null) {
                    Intrinsics.m("initialFolderSets");
                    throw null;
                }
                LinkedHashSet newFolderIds2 = kVar.s;
                if (newFolderIds2 == null) {
                    Intrinsics.m("selectedFolderIds");
                    throw null;
                }
                com.quizlet.data.repository.widget.b bVar = kVar.e;
                bVar.getClass();
                Intrinsics.checkNotNullParameter(setIds, "setIds");
                Intrinsics.checkNotNullParameter(originalFolderIds2, "originalFolderIds");
                Intrinsics.checkNotNullParameter(newFolderIds2, "newFolderIds");
                Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                io.reactivex.rxjava3.internal.operators.completable.c cVar3 = new io.reactivex.rxjava3.internal.operators.completable.c(((androidx.work.impl.model.c) bVar.c).c(stopToken, new androidx.work.impl.utils.o(bVar, setIds, originalFolderIds2, newFolderIds2, 4)), 6);
                Intrinsics.checkNotNullExpressionValue(cVar3, "ignoreElement(...)");
                io.reactivex.rxjava3.internal.observers.e eVarF2 = cVar3.f(new C4430d(3, kVar, setIds), new h(kVar, 1));
                Intrinsics.checkNotNullExpressionValue(eVarF2, "subscribe(...)");
                Intrinsics.checkNotNullParameter(eVarF2, "<this>");
                kVar.A(eVarF2);
                return true;
            }
        }
        timber.log.c.a.g("Finish clicked while in Initializing, Loading, or Error state. Canceling.", new Object[0]);
        y.l(a.a);
        return true;
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        setTitle(R.string.folder_add);
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        String str = SelectableFolderListFragment.v;
        if (supportFragmentManager.E(str) == null) {
            AbstractC1136h0 supportFragmentManager2 = getSupportFragmentManager();
            C1121a c1121aB = B.b(supportFragmentManager2, supportFragmentManager2);
            c1121aB.l(R.id.addClassContainer, new SelectableFolderListFragment(), str);
            c1121aB.g();
        }
        k kVar = this.q;
        if (kVar != null) {
            kVar.r.f(this, new com.quizlet.ads.ui.fragments.c(new G(this, 8), (byte) 0));
        } else {
            Intrinsics.m("viewModel");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return s;
    }
}
