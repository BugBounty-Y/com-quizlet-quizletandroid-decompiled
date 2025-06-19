package com.quizlet.quizletandroid.ui.setcreation.fragments;

import android.content.Context;
import android.content.Intent;
import android.graphics.PointF;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.Editable;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AnticipateOvershootInterpolator;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.Toast;
import androidx.appcompat.widget.U0;
import androidx.camera.core.AbstractC0151c;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.m0;
import androidx.lifecycle.Y;
import androidx.transition.C;
import androidx.transition.C1404g;
import androidx.transition.C1411n;
import androidx.transition.D;
import androidx.transition.F;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.mlkit_vision_barcode.H6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.f0;
import com.quizlet.quizletandroid.ui.setcreation.views.OcrCardView;
import com.quizlet.scandocument.model.EnumC4781a;
import com.quizlet.scandocument.ui.OcrDocumentView;
import com.quizlet.scandocument.ui.OcrImageView;
import com.quizlet.scandocument.ui.OcrToolbarView;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes3.dex */
public final class ScanDocumentFragment extends Hilt_ScanDocumentFragment<f0> implements m0 {
    public androidx.camera.camera2.internal.concurrent.a j;
    public com.quizlet.quizletandroid.ui.common.images.capture.a k;
    public androidx.camera.camera2.internal.compat.workaround.e l;
    public com.quizlet.quizletandroid.ui.setcreation.tracking.c m;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e n;
    public EditText o;
    public com.quizlet.quizletandroid.sessionhelpers.a p;
    public androidx.activity.result.b q;
    public final com.google.android.material.textfield.a r;

    public ScanDocumentFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new com.quizlet.login.recovery.forgotpassword.ui.e(this, 19), 20));
        this.n = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.setcreation.viewmodels.h.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 25), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 10), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 26));
        this.r = new com.google.android.material.textfield.a(this, 5);
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return "ScanDocumentFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.scan_document_fragment, viewGroup, false);
        int i = R.id.loading_spinner;
        RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.loading_spinner, viewInflate);
        if (relativeLayout != null) {
            i = R.id.ocr_card_view;
            OcrCardView ocrCardView = (OcrCardView) AbstractC3375o2.c(R.id.ocr_card_view, viewInflate);
            if (ocrCardView != null) {
                i = R.id.ocr_toolbar_view;
                OcrToolbarView ocrToolbarView = (OcrToolbarView) AbstractC3375o2.c(R.id.ocr_toolbar_view, viewInflate);
                if (ocrToolbarView != null) {
                    i = R.id.scan_document_view;
                    OcrDocumentView ocrDocumentView = (OcrDocumentView) AbstractC3375o2.c(R.id.scan_document_view, viewInflate);
                    if (ocrDocumentView != null) {
                        f0 f0Var = new f0((ConstraintLayout) viewInflate, relativeLayout, ocrCardView, ocrToolbarView, ocrDocumentView);
                        Intrinsics.checkNotNullExpressionValue(f0Var, "inflate(...)");
                        return f0Var;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void T() {
        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE0 = e0();
        String term = X();
        String definition = W();
        hVarE0.getClass();
        Intrinsics.checkNotNullParameter(term, "term");
        Intrinsics.checkNotNullParameter(definition, "definition");
        if (StringsKt.O(term) || StringsKt.O(definition)) {
            return;
        }
        hVarE0.H(term, definition);
    }

    public final void U() {
        EditText editText = this.o;
        if (editText == null) {
            Intrinsics.m("focusedView");
            throw null;
        }
        e0().I(editText.getText().toString());
        d0().getOcrImageView().a();
        EditText editText2 = this.o;
        if (editText2 == null) {
            Intrinsics.m("focusedView");
            throw null;
        }
        Editable text = editText2.getText();
        if (text != null) {
            text.clear();
        }
    }

    public final OcrCardView V() {
        OcrCardView ocrCardView = ((f0) J()).c;
        Intrinsics.checkNotNullExpressionValue(ocrCardView, "ocrCardView");
        return ocrCardView;
    }

    public final String W() {
        return StringsKt.g0(String.valueOf(V().getDefinitionFormField().getText())).toString();
    }

    public final String X() {
        return StringsKt.g0(String.valueOf(V().getWordFormField().getText())).toString();
    }

    public final com.quizlet.quizletandroid.ui.setcreation.tracking.c Y() {
        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar = this.m;
        if (cVar != null) {
            return cVar;
        }
        Intrinsics.m("eventLogger");
        throw null;
    }

    public final androidx.camera.camera2.internal.concurrent.a a0() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.j;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("imageCapturer");
        throw null;
    }

    public final RelativeLayout b0() {
        RelativeLayout loadingSpinner = ((f0) J()).b;
        Intrinsics.checkNotNullExpressionValue(loadingSpinner, "loadingSpinner");
        return loadingSpinner;
    }

    public final OcrToolbarView c0() {
        OcrToolbarView ocrToolbarView = ((f0) J()).d;
        Intrinsics.checkNotNullExpressionValue(ocrToolbarView, "ocrToolbarView");
        return ocrToolbarView;
    }

    public final OcrDocumentView d0() {
        OcrDocumentView scanDocumentView = ((f0) J()).e;
        Intrinsics.checkNotNullExpressionValue(scanDocumentView, "scanDocumentView");
        return scanDocumentView;
    }

    public final com.quizlet.quizletandroid.ui.setcreation.viewmodels.h e0() {
        return (com.quizlet.quizletandroid.ui.setcreation.viewmodels.h) this.n.getValue();
    }

    public final void f0(int i, int i2) {
        e.a aVar = new e.a(getContext());
        aVar.b = false;
        aVar.f(i);
        aVar.c(i2);
        aVar.e(R.string.scanning_error_dialog_ok_button, new m(this, 2));
        aVar.d(R.string.scanning_error_dialog_try_again_button, new m(this, 3));
        aVar.b().show();
    }

    public final void g0() {
        com.quizlet.quizletandroid.ui.setpage.b bVar = new com.quizlet.quizletandroid.ui.setpage.b();
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        Intrinsics.checkNotNullExpressionValue(childFragmentManager, "getChildFragmentManager(...)");
        AbstractC0151c.d(bVar, childFragmentManager, "AddImageBottomSheet");
    }

    @Override // androidx.fragment.app.Fragment
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i == 2001) {
            if (i2 == -1) {
                com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE0 = e0();
                hVarE0.G();
                ((r) hVarE0.c.o).i(new com.quizlet.quizletandroid.ui.setcreation.viewmodels.g(hVarE0, 0), io.reactivex.rxjava3.internal.functions.d.e);
                return;
            }
            return;
        }
        com.quizlet.quizletandroid.sessionhelpers.a aVar = this.p;
        if (aVar == null) {
            Intrinsics.m("editTracker");
            throw null;
        }
        aVar.c(i, i2, intent);
        a0().D(i, i2, getContext(), new com.quizlet.quizletandroid.k(this, 7));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Bundle arguments = getArguments();
        Long lValueOf = arguments != null ? Long.valueOf(arguments.getLong("setId")) : null;
        if (lValueOf != null) {
            com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE0 = e0();
            Zh zh = hVarE0.c;
            zh.getClass();
            com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
            bVar.b(lValueOf, DBStudySetFields.ID);
            com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
            com.quizlet.infra.legacysyncengine.net.c cVar = (com.quizlet.infra.legacysyncengine.net.c) zh.b;
            com.quizlet.infra.legacysyncengine.datasources.o oVar = new com.quizlet.infra.legacysyncengine.datasources.o(cVar, aVarA);
            Intrinsics.checkNotNullParameter(oVar, "<set-?>");
            zh.j = oVar;
            com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.TERM);
            bVar2.b(lValueOf, DBTermFields.SET);
            com.quizlet.infra.legacysyncengine.datasources.o oVar2 = new com.quizlet.infra.legacysyncengine.datasources.o(cVar, bVar2.a());
            Intrinsics.checkNotNullParameter(oVar2, "<set-?>");
            zh.k = oVar2;
            com.quizlet.quizletandroid.ui.setcreation.managers.l lVar = new com.quizlet.quizletandroid.ui.setcreation.managers.l(zh, 0);
            Intrinsics.checkNotNullParameter(lVar, "<set-?>");
            zh.l = lVar;
            com.quizlet.quizletandroid.ui.setcreation.managers.l lVar2 = new com.quizlet.quizletandroid.ui.setcreation.managers.l(zh, 1);
            Intrinsics.checkNotNullParameter(lVar2, "<set-?>");
            zh.m = lVar2;
            io.reactivex.rxjava3.internal.observers.e eVarI = ((r) zh.p).i(new com.quizlet.quizletandroid.ui.setcreation.viewmodels.g(hVarE0, 7), io.reactivex.rxjava3.internal.functions.d.e);
            Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
            Intrinsics.checkNotNullParameter(eVarI, "<this>");
            hVarE0.A(eVarI);
            io.reactivex.rxjava3.disposables.b bVarU = ((io.reactivex.rxjava3.subjects.d) zh.q).u(new com.quizlet.quizletandroid.ui.setcreation.viewmodels.g(hVarE0, 5), new com.quizlet.quizletandroid.ui.setcreation.viewmodels.g(hVarE0, 6), io.reactivex.rxjava3.internal.functions.d.c);
            Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
            Intrinsics.checkNotNullParameter(bVarU, "<this>");
            hVarE0.A(bVarU);
        }
        setHasOptionsMenu(true);
        androidx.activity.result.b bVarG = H6.g(this, new k(this, 1));
        Intrinsics.checkNotNullParameter(bVarG, "<set-?>");
        this.q = bVarG;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.quizletandroid.ui.common.images.capture.a aVar = this.k;
        if (aVar == null) {
            Intrinsics.m("imageCache");
            throw null;
        }
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        aVar.d(contextRequireContext);
        androidx.camera.camera2.internal.concurrent.a aVarA0 = a0();
        ((com.quizlet.qutils.image.capture.a) aVarA0.c).d(requireContext());
    }

    @Override // androidx.fragment.app.Fragment
    public final boolean onOptionsItemSelected(MenuItem item) {
        Intrinsics.checkNotNullParameter(item, "item");
        if (item.getItemId() != R.id.menu_set_complete) {
            return super.onOptionsItemSelected(item);
        }
        com.quizlet.quizletandroid.ui.setcreation.a aVar = new com.quizlet.quizletandroid.ui.setcreation.a();
        aVar.q = this;
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        Intrinsics.checkNotNullExpressionValue(childFragmentManager, "getChildFragmentManager(...)");
        AbstractC0151c.d(aVar, childFragmentManager, aVar.getTag());
        return true;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onPause() throws Exception {
        super.onPause();
        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE0 = e0();
        Zh zh = hVarE0.c;
        List list = (List) zh.n;
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (!((DBTerm) obj).hasValidUserContent()) {
                arrayList.add(obj);
            }
        }
        List list2 = (List) zh.n;
        ArrayList arrayList2 = new ArrayList();
        for (Object obj2 : list2) {
            if (((DBTerm) obj2).hasValidUserContent()) {
                arrayList2.add(obj2);
            }
        }
        if (arrayList2.size() >= 2 && !arrayList.isEmpty()) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                ((DBTerm) it2.next()).setDeleted(true);
            }
            ((com.quizlet.infra.legacysyncengine.managers.i) zh.f).a(arrayList, null);
        }
        Zh zh2 = hVarE0.c;
        com.quizlet.infra.legacysyncengine.datasources.o oVar = (com.quizlet.infra.legacysyncengine.datasources.o) zh2.k;
        if (oVar == null) {
            Intrinsics.m("termDataSource");
            throw null;
        }
        com.quizlet.quizletandroid.ui.setcreation.managers.l lVar = (com.quizlet.quizletandroid.ui.setcreation.managers.l) zh2.m;
        if (lVar == null) {
            Intrinsics.m("termsListener");
            throw null;
        }
        oVar.a(lVar);
        com.quizlet.infra.legacysyncengine.datasources.c cVarA = zh2.a();
        com.quizlet.quizletandroid.ui.setcreation.managers.l lVar2 = (com.quizlet.quizletandroid.ui.setcreation.managers.l) zh2.l;
        if (lVar2 == null) {
            Intrinsics.m("studySetListener");
            throw null;
        }
        cVarA.a(lVar2);
        DBStudySet dBStudySet = (DBStudySet) zh2.i;
        if (dBStudySet == null || dBStudySet.getIsCreated()) {
            return;
        }
        io.reactivex.rxjava3.core.i.p(dBStudySet).m(new com.quizlet.quizletandroid.k(zh2, 8), SubsamplingScaleImageView.TILE_SIZE_AUTO).m(new com.quizlet.quizletandroid.ui.activitycenter.views.i(zh2, 3), SubsamplingScaleImageView.TILE_SIZE_AUTO).t();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onRequestPermissionsResult(int i, String[] permissions, int[] grantResults) {
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        Intrinsics.checkNotNullParameter(grantResults, "grantResults");
        androidx.camera.camera2.internal.compat.workaround.e eVar = this.l;
        if (eVar != null) {
            androidx.camera.camera2.internal.compat.workaround.e.l(eVar, this, i, permissions, grantResults, new l(this, 2), new l(this, 3));
        } else {
            Intrinsics.m("permissionsManager");
            throw null;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        super.onResume();
        e0().G();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        a0().N(outState);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        if (!(e0().q instanceof com.quizlet.scandocument.model.k)) {
            OcrDocumentView ocrDocumentViewD0 = d0();
            com.quizlet.scandocument.model.p newState = com.quizlet.scandocument.model.p.a;
            ocrDocumentViewD0.q(newState);
            OcrToolbarView ocrToolbarViewC0 = c0();
            ocrToolbarViewC0.getClass();
            Intrinsics.checkNotNullParameter(newState, "newState");
            ocrToolbarViewC0.C = newState;
            ocrToolbarViewC0.r();
        }
        OcrCardView ocrCardViewV = V();
        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE0 = e0();
        hVarE0.getClass();
        U0 textWatcher = new U0(hVarE0, 3);
        ocrCardViewV.getClass();
        Intrinsics.checkNotNullParameter(textWatcher, "textWatcher");
        ocrCardViewV.a.e(textWatcher);
        ocrCardViewV.b.e(textWatcher);
        QFormField wordFormField = V().getWordFormField();
        com.google.android.material.textfield.a aVar = this.r;
        wordFormField.c(aVar);
        V().getDefinitionFormField().c(aVar);
        this.o = V().getWordFormField().getEditText();
        e0().j.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(16, new k(this, 0)));
        e0().k.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(16, new k(this, 3)));
        e0().l.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(16, new k(this, 4)));
        e0().g.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(16, new k(this, 5)));
        e0().h.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(16, new k(this, 6)));
        e0().i.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(16, new k(this, 7)));
        e0().m.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(16, new k(this, 8)));
        io.reactivex.rxjava3.subjects.d dVar = c0().x;
        final int i = 0;
        io.reactivex.rxjava3.functions.d dVar2 = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.o
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i2;
                ArrayList arrayList;
                ArrayList arrayList2;
                switch (i) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        this.b.G(p0);
                        return;
                    case 1:
                        Unit it2 = (Unit) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE02 = scanDocumentFragment.e0();
                        String term = scanDocumentFragment.X();
                        String definition = scanDocumentFragment.W();
                        hVarE02.getClass();
                        Intrinsics.checkNotNullParameter(term, "term");
                        Intrinsics.checkNotNullParameter(definition, "definition");
                        hVarE02.f.a.y(hVarE02.e.b.size() + hVarE02.n);
                        hVarE02.H(term, definition);
                        Y y = hVarE02.l;
                        Integer num = (Integer) y.d();
                        y.l(Integer.valueOf((num != null ? num.intValue() : 1) + 1));
                        scanDocumentFragment.d0().getOcrImageView().a();
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE03 = scanDocumentFragment.e0();
                        com.quizlet.scandocument.a aVar2 = hVarE03.e;
                        hVarE03.n = aVar2.b.size();
                        aVar2.b.clear();
                        OcrCardView ocrCardViewV2 = scanDocumentFragment.V();
                        ocrCardViewV2.getClass();
                        C1404g c1404g = new C1404g(1);
                        c1404g.c = 350L;
                        ArrayList arrayList3 = c1404g.f;
                        CardView cardView = ocrCardViewV2.d;
                        arrayList3.add(cardView);
                        Intrinsics.checkNotNullExpressionValue(c1404g, "addTarget(...)");
                        androidx.transition.r rVar = new androidx.transition.r();
                        rVar.H = androidx.transition.r.K;
                        rVar.v = new C1411n();
                        rVar.b = 150L;
                        rVar.c = 350L;
                        rVar.d = new AnticipateOvershootInterpolator();
                        ArrayList arrayList4 = rVar.f;
                        ImageView imageView = ocrCardViewV2.e;
                        arrayList4.add(imageView);
                        ArrayList arrayList5 = rVar.f;
                        QTextView qTextView = ocrCardViewV2.f;
                        arrayList5.add(qTextView);
                        rVar.b(new D(ocrCardViewV2, 1));
                        Intrinsics.checkNotNullExpressionValue(rVar, "addListener(...)");
                        F f = new F();
                        f.R(c1404g);
                        f.R(rVar);
                        f.T(0);
                        C.a(ocrCardViewV2.g, f);
                        cardView.setVisibility(0);
                        imageView.setVisibility(0);
                        qTextView.setVisibility(0);
                        cardView.setVisibility(0);
                        OcrCardView ocrCardViewV3 = scanDocumentFragment.V();
                        QFormField qFormField = ocrCardViewV3.a;
                        Editable text = qFormField.getEditText().getText();
                        if (text != null) {
                            text.clear();
                        }
                        Editable text2 = ocrCardViewV3.b.getEditText().getText();
                        if (text2 != null) {
                            text2.clear();
                        }
                        Intrinsics.checkNotNullParameter(qFormField, "<this>");
                        qFormField.requestFocus();
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 1, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        return;
                    case 2:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        this.b.G(p02);
                        return;
                    case 3:
                        EnumC4781a inputMethod = (EnumC4781a) obj;
                        Intrinsics.checkNotNullParameter(inputMethod, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE04 = this.b.e0();
                        hVarE04.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar = hVarE04.f;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        int iOrdinal = inputMethod.ordinal();
                        EventLogger eventLogger = cVar.a;
                        if (iOrdinal == 0) {
                            eventLogger.z("ocr_tap_ocr");
                        } else {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger.z("ocr_tap_keyboard");
                        }
                        hVarE04.j.l(inputMethod);
                        return;
                    case 4:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        this.b.G(p03);
                        return;
                    case 5:
                        com.quizlet.scandocument.model.b interactionMode = (com.quizlet.scandocument.model.b) obj;
                        Intrinsics.checkNotNullParameter(interactionMode, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE05 = this.b.e0();
                        hVarE05.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar2 = hVarE05.f;
                        cVar2.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        int iOrdinal2 = interactionMode.ordinal();
                        EventLogger eventLogger2 = cVar2.a;
                        if (iOrdinal2 == 0) {
                            eventLogger2.z("ocr_tap_select_mode");
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger2.z("ocr_tap_move_mode");
                        }
                        hVarE05.k.l(interactionMode);
                        return;
                    case 6:
                        io.reactivex.rxjava3.disposables.b p04 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p04, "p0");
                        this.b.G(p04);
                        return;
                    default:
                        PointF touchEvent = (PointF) obj;
                        Intrinsics.checkNotNullParameter(touchEvent, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE06 = this.b.e0();
                        hVarE06.getClass();
                        Intrinsics.checkNotNullParameter(touchEvent, "touchEvent");
                        Intrinsics.checkNotNullParameter(touchEvent, "<this>");
                        com.quizlet.scandocument.graphics.a sourceTouch = new com.quizlet.scandocument.graphics.a(touchEvent.x, touchEvent.y);
                        com.quizlet.scandocument.a aVar3 = hVarE06.e;
                        aVar3.getClass();
                        Intrinsics.checkNotNullParameter(sourceTouch, "sourceTouch");
                        ArrayList arrayList6 = aVar3.a;
                        int size = arrayList6.size() - 1;
                        TreeSet treeSet = aVar3.b;
                        if (size >= 0) {
                            i2 = 0;
                            while (true) {
                                if (treeSet.contains(Integer.valueOf(i2))) {
                                    arrayList = arrayList6;
                                } else {
                                    com.quizlet.scandocument.graphics.b bVar = (com.quizlet.scandocument.graphics.b) arrayList6.get(i2);
                                    int i3 = bVar.c;
                                    int i4 = i3 - 1;
                                    int i5 = 0;
                                    boolean z = false;
                                    while (i5 < i3) {
                                        float[] fArr = bVar.b;
                                        float f2 = fArr[i5];
                                        float f3 = sourceTouch.b;
                                        if ((f2 >= f3 || fArr[i4] < f3) && (fArr[i4] >= f3 || f2 < f3)) {
                                            arrayList2 = arrayList6;
                                        } else {
                                            float[] fArr2 = bVar.a;
                                            arrayList2 = arrayList6;
                                            float f4 = fArr2[i5];
                                            if (android.support.v4.media.session.a.a(fArr2[i4], f4, (f3 - f2) / (fArr[i4] - f2), f4) < sourceTouch.a) {
                                                z = !z;
                                            }
                                        }
                                        i4 = i5;
                                        i5++;
                                        arrayList6 = arrayList2;
                                    }
                                    arrayList = arrayList6;
                                    if (z) {
                                    }
                                }
                                if (i2 != size) {
                                    i2++;
                                    arrayList6 = arrayList;
                                }
                            }
                            i2 = -1;
                        } else {
                            i2 = -1;
                        }
                        if (i2 >= 0) {
                            treeSet.add(Integer.valueOf(i2));
                            aVar3.d.b(Integer.valueOf(i2));
                            aVar3.c.add(Integer.valueOf(i2));
                            return;
                        }
                        return;
                }
            }
        };
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        dVar.getClass();
        io.reactivex.rxjava3.internal.operators.observable.C c = new io.reactivex.rxjava3.internal.operators.observable.C(dVar, dVar2, bVar);
        final int i2 = 1;
        io.reactivex.rxjava3.functions.d dVar3 = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.o
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i22;
                ArrayList arrayList;
                ArrayList arrayList2;
                switch (i2) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        this.b.G(p0);
                        return;
                    case 1:
                        Unit it2 = (Unit) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE02 = scanDocumentFragment.e0();
                        String term = scanDocumentFragment.X();
                        String definition = scanDocumentFragment.W();
                        hVarE02.getClass();
                        Intrinsics.checkNotNullParameter(term, "term");
                        Intrinsics.checkNotNullParameter(definition, "definition");
                        hVarE02.f.a.y(hVarE02.e.b.size() + hVarE02.n);
                        hVarE02.H(term, definition);
                        Y y = hVarE02.l;
                        Integer num = (Integer) y.d();
                        y.l(Integer.valueOf((num != null ? num.intValue() : 1) + 1));
                        scanDocumentFragment.d0().getOcrImageView().a();
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE03 = scanDocumentFragment.e0();
                        com.quizlet.scandocument.a aVar2 = hVarE03.e;
                        hVarE03.n = aVar2.b.size();
                        aVar2.b.clear();
                        OcrCardView ocrCardViewV2 = scanDocumentFragment.V();
                        ocrCardViewV2.getClass();
                        C1404g c1404g = new C1404g(1);
                        c1404g.c = 350L;
                        ArrayList arrayList3 = c1404g.f;
                        CardView cardView = ocrCardViewV2.d;
                        arrayList3.add(cardView);
                        Intrinsics.checkNotNullExpressionValue(c1404g, "addTarget(...)");
                        androidx.transition.r rVar = new androidx.transition.r();
                        rVar.H = androidx.transition.r.K;
                        rVar.v = new C1411n();
                        rVar.b = 150L;
                        rVar.c = 350L;
                        rVar.d = new AnticipateOvershootInterpolator();
                        ArrayList arrayList4 = rVar.f;
                        ImageView imageView = ocrCardViewV2.e;
                        arrayList4.add(imageView);
                        ArrayList arrayList5 = rVar.f;
                        QTextView qTextView = ocrCardViewV2.f;
                        arrayList5.add(qTextView);
                        rVar.b(new D(ocrCardViewV2, 1));
                        Intrinsics.checkNotNullExpressionValue(rVar, "addListener(...)");
                        F f = new F();
                        f.R(c1404g);
                        f.R(rVar);
                        f.T(0);
                        C.a(ocrCardViewV2.g, f);
                        cardView.setVisibility(0);
                        imageView.setVisibility(0);
                        qTextView.setVisibility(0);
                        cardView.setVisibility(0);
                        OcrCardView ocrCardViewV3 = scanDocumentFragment.V();
                        QFormField qFormField = ocrCardViewV3.a;
                        Editable text = qFormField.getEditText().getText();
                        if (text != null) {
                            text.clear();
                        }
                        Editable text2 = ocrCardViewV3.b.getEditText().getText();
                        if (text2 != null) {
                            text2.clear();
                        }
                        Intrinsics.checkNotNullParameter(qFormField, "<this>");
                        qFormField.requestFocus();
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 1, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        return;
                    case 2:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        this.b.G(p02);
                        return;
                    case 3:
                        EnumC4781a inputMethod = (EnumC4781a) obj;
                        Intrinsics.checkNotNullParameter(inputMethod, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE04 = this.b.e0();
                        hVarE04.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar = hVarE04.f;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        int iOrdinal = inputMethod.ordinal();
                        EventLogger eventLogger = cVar.a;
                        if (iOrdinal == 0) {
                            eventLogger.z("ocr_tap_ocr");
                        } else {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger.z("ocr_tap_keyboard");
                        }
                        hVarE04.j.l(inputMethod);
                        return;
                    case 4:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        this.b.G(p03);
                        return;
                    case 5:
                        com.quizlet.scandocument.model.b interactionMode = (com.quizlet.scandocument.model.b) obj;
                        Intrinsics.checkNotNullParameter(interactionMode, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE05 = this.b.e0();
                        hVarE05.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar2 = hVarE05.f;
                        cVar2.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        int iOrdinal2 = interactionMode.ordinal();
                        EventLogger eventLogger2 = cVar2.a;
                        if (iOrdinal2 == 0) {
                            eventLogger2.z("ocr_tap_select_mode");
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger2.z("ocr_tap_move_mode");
                        }
                        hVarE05.k.l(interactionMode);
                        return;
                    case 6:
                        io.reactivex.rxjava3.disposables.b p04 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p04, "p0");
                        this.b.G(p04);
                        return;
                    default:
                        PointF touchEvent = (PointF) obj;
                        Intrinsics.checkNotNullParameter(touchEvent, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE06 = this.b.e0();
                        hVarE06.getClass();
                        Intrinsics.checkNotNullParameter(touchEvent, "touchEvent");
                        Intrinsics.checkNotNullParameter(touchEvent, "<this>");
                        com.quizlet.scandocument.graphics.a sourceTouch = new com.quizlet.scandocument.graphics.a(touchEvent.x, touchEvent.y);
                        com.quizlet.scandocument.a aVar3 = hVarE06.e;
                        aVar3.getClass();
                        Intrinsics.checkNotNullParameter(sourceTouch, "sourceTouch");
                        ArrayList arrayList6 = aVar3.a;
                        int size = arrayList6.size() - 1;
                        TreeSet treeSet = aVar3.b;
                        if (size >= 0) {
                            i22 = 0;
                            while (true) {
                                if (treeSet.contains(Integer.valueOf(i22))) {
                                    arrayList = arrayList6;
                                } else {
                                    com.quizlet.scandocument.graphics.b bVar2 = (com.quizlet.scandocument.graphics.b) arrayList6.get(i22);
                                    int i3 = bVar2.c;
                                    int i4 = i3 - 1;
                                    int i5 = 0;
                                    boolean z = false;
                                    while (i5 < i3) {
                                        float[] fArr = bVar2.b;
                                        float f2 = fArr[i5];
                                        float f3 = sourceTouch.b;
                                        if ((f2 >= f3 || fArr[i4] < f3) && (fArr[i4] >= f3 || f2 < f3)) {
                                            arrayList2 = arrayList6;
                                        } else {
                                            float[] fArr2 = bVar2.a;
                                            arrayList2 = arrayList6;
                                            float f4 = fArr2[i5];
                                            if (android.support.v4.media.session.a.a(fArr2[i4], f4, (f3 - f2) / (fArr[i4] - f2), f4) < sourceTouch.a) {
                                                z = !z;
                                            }
                                        }
                                        i4 = i5;
                                        i5++;
                                        arrayList6 = arrayList2;
                                    }
                                    arrayList = arrayList6;
                                    if (z) {
                                    }
                                }
                                if (i22 != size) {
                                    i22++;
                                    arrayList6 = arrayList;
                                }
                            }
                            i22 = -1;
                        } else {
                            i22 = -1;
                        }
                        if (i22 >= 0) {
                            treeSet.add(Integer.valueOf(i22));
                            aVar3.d.b(Integer.valueOf(i22));
                            aVar3.c.add(Integer.valueOf(i22));
                            return;
                        }
                        return;
                }
            }
        };
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
        c.u(dVar3, gVar, bVar);
        io.reactivex.rxjava3.subjects.d dVar4 = c0().u;
        final int i3 = 2;
        io.reactivex.rxjava3.functions.d dVar5 = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.o
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i22;
                ArrayList arrayList;
                ArrayList arrayList2;
                switch (i3) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        this.b.G(p0);
                        return;
                    case 1:
                        Unit it2 = (Unit) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE02 = scanDocumentFragment.e0();
                        String term = scanDocumentFragment.X();
                        String definition = scanDocumentFragment.W();
                        hVarE02.getClass();
                        Intrinsics.checkNotNullParameter(term, "term");
                        Intrinsics.checkNotNullParameter(definition, "definition");
                        hVarE02.f.a.y(hVarE02.e.b.size() + hVarE02.n);
                        hVarE02.H(term, definition);
                        Y y = hVarE02.l;
                        Integer num = (Integer) y.d();
                        y.l(Integer.valueOf((num != null ? num.intValue() : 1) + 1));
                        scanDocumentFragment.d0().getOcrImageView().a();
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE03 = scanDocumentFragment.e0();
                        com.quizlet.scandocument.a aVar2 = hVarE03.e;
                        hVarE03.n = aVar2.b.size();
                        aVar2.b.clear();
                        OcrCardView ocrCardViewV2 = scanDocumentFragment.V();
                        ocrCardViewV2.getClass();
                        C1404g c1404g = new C1404g(1);
                        c1404g.c = 350L;
                        ArrayList arrayList3 = c1404g.f;
                        CardView cardView = ocrCardViewV2.d;
                        arrayList3.add(cardView);
                        Intrinsics.checkNotNullExpressionValue(c1404g, "addTarget(...)");
                        androidx.transition.r rVar = new androidx.transition.r();
                        rVar.H = androidx.transition.r.K;
                        rVar.v = new C1411n();
                        rVar.b = 150L;
                        rVar.c = 350L;
                        rVar.d = new AnticipateOvershootInterpolator();
                        ArrayList arrayList4 = rVar.f;
                        ImageView imageView = ocrCardViewV2.e;
                        arrayList4.add(imageView);
                        ArrayList arrayList5 = rVar.f;
                        QTextView qTextView = ocrCardViewV2.f;
                        arrayList5.add(qTextView);
                        rVar.b(new D(ocrCardViewV2, 1));
                        Intrinsics.checkNotNullExpressionValue(rVar, "addListener(...)");
                        F f = new F();
                        f.R(c1404g);
                        f.R(rVar);
                        f.T(0);
                        C.a(ocrCardViewV2.g, f);
                        cardView.setVisibility(0);
                        imageView.setVisibility(0);
                        qTextView.setVisibility(0);
                        cardView.setVisibility(0);
                        OcrCardView ocrCardViewV3 = scanDocumentFragment.V();
                        QFormField qFormField = ocrCardViewV3.a;
                        Editable text = qFormField.getEditText().getText();
                        if (text != null) {
                            text.clear();
                        }
                        Editable text2 = ocrCardViewV3.b.getEditText().getText();
                        if (text2 != null) {
                            text2.clear();
                        }
                        Intrinsics.checkNotNullParameter(qFormField, "<this>");
                        qFormField.requestFocus();
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 1, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        return;
                    case 2:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        this.b.G(p02);
                        return;
                    case 3:
                        EnumC4781a inputMethod = (EnumC4781a) obj;
                        Intrinsics.checkNotNullParameter(inputMethod, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE04 = this.b.e0();
                        hVarE04.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar = hVarE04.f;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        int iOrdinal = inputMethod.ordinal();
                        EventLogger eventLogger = cVar.a;
                        if (iOrdinal == 0) {
                            eventLogger.z("ocr_tap_ocr");
                        } else {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger.z("ocr_tap_keyboard");
                        }
                        hVarE04.j.l(inputMethod);
                        return;
                    case 4:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        this.b.G(p03);
                        return;
                    case 5:
                        com.quizlet.scandocument.model.b interactionMode = (com.quizlet.scandocument.model.b) obj;
                        Intrinsics.checkNotNullParameter(interactionMode, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE05 = this.b.e0();
                        hVarE05.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar2 = hVarE05.f;
                        cVar2.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        int iOrdinal2 = interactionMode.ordinal();
                        EventLogger eventLogger2 = cVar2.a;
                        if (iOrdinal2 == 0) {
                            eventLogger2.z("ocr_tap_select_mode");
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger2.z("ocr_tap_move_mode");
                        }
                        hVarE05.k.l(interactionMode);
                        return;
                    case 6:
                        io.reactivex.rxjava3.disposables.b p04 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p04, "p0");
                        this.b.G(p04);
                        return;
                    default:
                        PointF touchEvent = (PointF) obj;
                        Intrinsics.checkNotNullParameter(touchEvent, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE06 = this.b.e0();
                        hVarE06.getClass();
                        Intrinsics.checkNotNullParameter(touchEvent, "touchEvent");
                        Intrinsics.checkNotNullParameter(touchEvent, "<this>");
                        com.quizlet.scandocument.graphics.a sourceTouch = new com.quizlet.scandocument.graphics.a(touchEvent.x, touchEvent.y);
                        com.quizlet.scandocument.a aVar3 = hVarE06.e;
                        aVar3.getClass();
                        Intrinsics.checkNotNullParameter(sourceTouch, "sourceTouch");
                        ArrayList arrayList6 = aVar3.a;
                        int size = arrayList6.size() - 1;
                        TreeSet treeSet = aVar3.b;
                        if (size >= 0) {
                            i22 = 0;
                            while (true) {
                                if (treeSet.contains(Integer.valueOf(i22))) {
                                    arrayList = arrayList6;
                                } else {
                                    com.quizlet.scandocument.graphics.b bVar2 = (com.quizlet.scandocument.graphics.b) arrayList6.get(i22);
                                    int i32 = bVar2.c;
                                    int i4 = i32 - 1;
                                    int i5 = 0;
                                    boolean z = false;
                                    while (i5 < i32) {
                                        float[] fArr = bVar2.b;
                                        float f2 = fArr[i5];
                                        float f3 = sourceTouch.b;
                                        if ((f2 >= f3 || fArr[i4] < f3) && (fArr[i4] >= f3 || f2 < f3)) {
                                            arrayList2 = arrayList6;
                                        } else {
                                            float[] fArr2 = bVar2.a;
                                            arrayList2 = arrayList6;
                                            float f4 = fArr2[i5];
                                            if (android.support.v4.media.session.a.a(fArr2[i4], f4, (f3 - f2) / (fArr[i4] - f2), f4) < sourceTouch.a) {
                                                z = !z;
                                            }
                                        }
                                        i4 = i5;
                                        i5++;
                                        arrayList6 = arrayList2;
                                    }
                                    arrayList = arrayList6;
                                    if (z) {
                                    }
                                }
                                if (i22 != size) {
                                    i22++;
                                    arrayList6 = arrayList;
                                }
                            }
                            i22 = -1;
                        } else {
                            i22 = -1;
                        }
                        if (i22 >= 0) {
                            treeSet.add(Integer.valueOf(i22));
                            aVar3.d.b(Integer.valueOf(i22));
                            aVar3.c.add(Integer.valueOf(i22));
                            return;
                        }
                        return;
                }
            }
        };
        dVar4.getClass();
        io.reactivex.rxjava3.internal.operators.observable.C c2 = new io.reactivex.rxjava3.internal.operators.observable.C(dVar4, dVar5, bVar);
        final int i4 = 3;
        c2.u(new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.o
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i22;
                ArrayList arrayList;
                ArrayList arrayList2;
                switch (i4) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        this.b.G(p0);
                        return;
                    case 1:
                        Unit it2 = (Unit) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE02 = scanDocumentFragment.e0();
                        String term = scanDocumentFragment.X();
                        String definition = scanDocumentFragment.W();
                        hVarE02.getClass();
                        Intrinsics.checkNotNullParameter(term, "term");
                        Intrinsics.checkNotNullParameter(definition, "definition");
                        hVarE02.f.a.y(hVarE02.e.b.size() + hVarE02.n);
                        hVarE02.H(term, definition);
                        Y y = hVarE02.l;
                        Integer num = (Integer) y.d();
                        y.l(Integer.valueOf((num != null ? num.intValue() : 1) + 1));
                        scanDocumentFragment.d0().getOcrImageView().a();
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE03 = scanDocumentFragment.e0();
                        com.quizlet.scandocument.a aVar2 = hVarE03.e;
                        hVarE03.n = aVar2.b.size();
                        aVar2.b.clear();
                        OcrCardView ocrCardViewV2 = scanDocumentFragment.V();
                        ocrCardViewV2.getClass();
                        C1404g c1404g = new C1404g(1);
                        c1404g.c = 350L;
                        ArrayList arrayList3 = c1404g.f;
                        CardView cardView = ocrCardViewV2.d;
                        arrayList3.add(cardView);
                        Intrinsics.checkNotNullExpressionValue(c1404g, "addTarget(...)");
                        androidx.transition.r rVar = new androidx.transition.r();
                        rVar.H = androidx.transition.r.K;
                        rVar.v = new C1411n();
                        rVar.b = 150L;
                        rVar.c = 350L;
                        rVar.d = new AnticipateOvershootInterpolator();
                        ArrayList arrayList4 = rVar.f;
                        ImageView imageView = ocrCardViewV2.e;
                        arrayList4.add(imageView);
                        ArrayList arrayList5 = rVar.f;
                        QTextView qTextView = ocrCardViewV2.f;
                        arrayList5.add(qTextView);
                        rVar.b(new D(ocrCardViewV2, 1));
                        Intrinsics.checkNotNullExpressionValue(rVar, "addListener(...)");
                        F f = new F();
                        f.R(c1404g);
                        f.R(rVar);
                        f.T(0);
                        C.a(ocrCardViewV2.g, f);
                        cardView.setVisibility(0);
                        imageView.setVisibility(0);
                        qTextView.setVisibility(0);
                        cardView.setVisibility(0);
                        OcrCardView ocrCardViewV3 = scanDocumentFragment.V();
                        QFormField qFormField = ocrCardViewV3.a;
                        Editable text = qFormField.getEditText().getText();
                        if (text != null) {
                            text.clear();
                        }
                        Editable text2 = ocrCardViewV3.b.getEditText().getText();
                        if (text2 != null) {
                            text2.clear();
                        }
                        Intrinsics.checkNotNullParameter(qFormField, "<this>");
                        qFormField.requestFocus();
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 1, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        return;
                    case 2:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        this.b.G(p02);
                        return;
                    case 3:
                        EnumC4781a inputMethod = (EnumC4781a) obj;
                        Intrinsics.checkNotNullParameter(inputMethod, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE04 = this.b.e0();
                        hVarE04.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar = hVarE04.f;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        int iOrdinal = inputMethod.ordinal();
                        EventLogger eventLogger = cVar.a;
                        if (iOrdinal == 0) {
                            eventLogger.z("ocr_tap_ocr");
                        } else {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger.z("ocr_tap_keyboard");
                        }
                        hVarE04.j.l(inputMethod);
                        return;
                    case 4:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        this.b.G(p03);
                        return;
                    case 5:
                        com.quizlet.scandocument.model.b interactionMode = (com.quizlet.scandocument.model.b) obj;
                        Intrinsics.checkNotNullParameter(interactionMode, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE05 = this.b.e0();
                        hVarE05.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar2 = hVarE05.f;
                        cVar2.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        int iOrdinal2 = interactionMode.ordinal();
                        EventLogger eventLogger2 = cVar2.a;
                        if (iOrdinal2 == 0) {
                            eventLogger2.z("ocr_tap_select_mode");
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger2.z("ocr_tap_move_mode");
                        }
                        hVarE05.k.l(interactionMode);
                        return;
                    case 6:
                        io.reactivex.rxjava3.disposables.b p04 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p04, "p0");
                        this.b.G(p04);
                        return;
                    default:
                        PointF touchEvent = (PointF) obj;
                        Intrinsics.checkNotNullParameter(touchEvent, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE06 = this.b.e0();
                        hVarE06.getClass();
                        Intrinsics.checkNotNullParameter(touchEvent, "touchEvent");
                        Intrinsics.checkNotNullParameter(touchEvent, "<this>");
                        com.quizlet.scandocument.graphics.a sourceTouch = new com.quizlet.scandocument.graphics.a(touchEvent.x, touchEvent.y);
                        com.quizlet.scandocument.a aVar3 = hVarE06.e;
                        aVar3.getClass();
                        Intrinsics.checkNotNullParameter(sourceTouch, "sourceTouch");
                        ArrayList arrayList6 = aVar3.a;
                        int size = arrayList6.size() - 1;
                        TreeSet treeSet = aVar3.b;
                        if (size >= 0) {
                            i22 = 0;
                            while (true) {
                                if (treeSet.contains(Integer.valueOf(i22))) {
                                    arrayList = arrayList6;
                                } else {
                                    com.quizlet.scandocument.graphics.b bVar2 = (com.quizlet.scandocument.graphics.b) arrayList6.get(i22);
                                    int i32 = bVar2.c;
                                    int i42 = i32 - 1;
                                    int i5 = 0;
                                    boolean z = false;
                                    while (i5 < i32) {
                                        float[] fArr = bVar2.b;
                                        float f2 = fArr[i5];
                                        float f3 = sourceTouch.b;
                                        if ((f2 >= f3 || fArr[i42] < f3) && (fArr[i42] >= f3 || f2 < f3)) {
                                            arrayList2 = arrayList6;
                                        } else {
                                            float[] fArr2 = bVar2.a;
                                            arrayList2 = arrayList6;
                                            float f4 = fArr2[i5];
                                            if (android.support.v4.media.session.a.a(fArr2[i42], f4, (f3 - f2) / (fArr[i42] - f2), f4) < sourceTouch.a) {
                                                z = !z;
                                            }
                                        }
                                        i42 = i5;
                                        i5++;
                                        arrayList6 = arrayList2;
                                    }
                                    arrayList = arrayList6;
                                    if (z) {
                                    }
                                }
                                if (i22 != size) {
                                    i22++;
                                    arrayList6 = arrayList;
                                }
                            }
                            i22 = -1;
                        } else {
                            i22 = -1;
                        }
                        if (i22 >= 0) {
                            treeSet.add(Integer.valueOf(i22));
                            aVar3.d.b(Integer.valueOf(i22));
                            aVar3.c.add(Integer.valueOf(i22));
                            return;
                        }
                        return;
                }
            }
        }, gVar, bVar);
        io.reactivex.rxjava3.subjects.d dVar6 = c0().v;
        final int i5 = 4;
        io.reactivex.rxjava3.functions.d dVar7 = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.o
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i22;
                ArrayList arrayList;
                ArrayList arrayList2;
                switch (i5) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        this.b.G(p0);
                        return;
                    case 1:
                        Unit it2 = (Unit) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE02 = scanDocumentFragment.e0();
                        String term = scanDocumentFragment.X();
                        String definition = scanDocumentFragment.W();
                        hVarE02.getClass();
                        Intrinsics.checkNotNullParameter(term, "term");
                        Intrinsics.checkNotNullParameter(definition, "definition");
                        hVarE02.f.a.y(hVarE02.e.b.size() + hVarE02.n);
                        hVarE02.H(term, definition);
                        Y y = hVarE02.l;
                        Integer num = (Integer) y.d();
                        y.l(Integer.valueOf((num != null ? num.intValue() : 1) + 1));
                        scanDocumentFragment.d0().getOcrImageView().a();
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE03 = scanDocumentFragment.e0();
                        com.quizlet.scandocument.a aVar2 = hVarE03.e;
                        hVarE03.n = aVar2.b.size();
                        aVar2.b.clear();
                        OcrCardView ocrCardViewV2 = scanDocumentFragment.V();
                        ocrCardViewV2.getClass();
                        C1404g c1404g = new C1404g(1);
                        c1404g.c = 350L;
                        ArrayList arrayList3 = c1404g.f;
                        CardView cardView = ocrCardViewV2.d;
                        arrayList3.add(cardView);
                        Intrinsics.checkNotNullExpressionValue(c1404g, "addTarget(...)");
                        androidx.transition.r rVar = new androidx.transition.r();
                        rVar.H = androidx.transition.r.K;
                        rVar.v = new C1411n();
                        rVar.b = 150L;
                        rVar.c = 350L;
                        rVar.d = new AnticipateOvershootInterpolator();
                        ArrayList arrayList4 = rVar.f;
                        ImageView imageView = ocrCardViewV2.e;
                        arrayList4.add(imageView);
                        ArrayList arrayList5 = rVar.f;
                        QTextView qTextView = ocrCardViewV2.f;
                        arrayList5.add(qTextView);
                        rVar.b(new D(ocrCardViewV2, 1));
                        Intrinsics.checkNotNullExpressionValue(rVar, "addListener(...)");
                        F f = new F();
                        f.R(c1404g);
                        f.R(rVar);
                        f.T(0);
                        C.a(ocrCardViewV2.g, f);
                        cardView.setVisibility(0);
                        imageView.setVisibility(0);
                        qTextView.setVisibility(0);
                        cardView.setVisibility(0);
                        OcrCardView ocrCardViewV3 = scanDocumentFragment.V();
                        QFormField qFormField = ocrCardViewV3.a;
                        Editable text = qFormField.getEditText().getText();
                        if (text != null) {
                            text.clear();
                        }
                        Editable text2 = ocrCardViewV3.b.getEditText().getText();
                        if (text2 != null) {
                            text2.clear();
                        }
                        Intrinsics.checkNotNullParameter(qFormField, "<this>");
                        qFormField.requestFocus();
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 1, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        return;
                    case 2:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        this.b.G(p02);
                        return;
                    case 3:
                        EnumC4781a inputMethod = (EnumC4781a) obj;
                        Intrinsics.checkNotNullParameter(inputMethod, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE04 = this.b.e0();
                        hVarE04.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar = hVarE04.f;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        int iOrdinal = inputMethod.ordinal();
                        EventLogger eventLogger = cVar.a;
                        if (iOrdinal == 0) {
                            eventLogger.z("ocr_tap_ocr");
                        } else {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger.z("ocr_tap_keyboard");
                        }
                        hVarE04.j.l(inputMethod);
                        return;
                    case 4:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        this.b.G(p03);
                        return;
                    case 5:
                        com.quizlet.scandocument.model.b interactionMode = (com.quizlet.scandocument.model.b) obj;
                        Intrinsics.checkNotNullParameter(interactionMode, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE05 = this.b.e0();
                        hVarE05.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar2 = hVarE05.f;
                        cVar2.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        int iOrdinal2 = interactionMode.ordinal();
                        EventLogger eventLogger2 = cVar2.a;
                        if (iOrdinal2 == 0) {
                            eventLogger2.z("ocr_tap_select_mode");
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger2.z("ocr_tap_move_mode");
                        }
                        hVarE05.k.l(interactionMode);
                        return;
                    case 6:
                        io.reactivex.rxjava3.disposables.b p04 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p04, "p0");
                        this.b.G(p04);
                        return;
                    default:
                        PointF touchEvent = (PointF) obj;
                        Intrinsics.checkNotNullParameter(touchEvent, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE06 = this.b.e0();
                        hVarE06.getClass();
                        Intrinsics.checkNotNullParameter(touchEvent, "touchEvent");
                        Intrinsics.checkNotNullParameter(touchEvent, "<this>");
                        com.quizlet.scandocument.graphics.a sourceTouch = new com.quizlet.scandocument.graphics.a(touchEvent.x, touchEvent.y);
                        com.quizlet.scandocument.a aVar3 = hVarE06.e;
                        aVar3.getClass();
                        Intrinsics.checkNotNullParameter(sourceTouch, "sourceTouch");
                        ArrayList arrayList6 = aVar3.a;
                        int size = arrayList6.size() - 1;
                        TreeSet treeSet = aVar3.b;
                        if (size >= 0) {
                            i22 = 0;
                            while (true) {
                                if (treeSet.contains(Integer.valueOf(i22))) {
                                    arrayList = arrayList6;
                                } else {
                                    com.quizlet.scandocument.graphics.b bVar2 = (com.quizlet.scandocument.graphics.b) arrayList6.get(i22);
                                    int i32 = bVar2.c;
                                    int i42 = i32 - 1;
                                    int i52 = 0;
                                    boolean z = false;
                                    while (i52 < i32) {
                                        float[] fArr = bVar2.b;
                                        float f2 = fArr[i52];
                                        float f3 = sourceTouch.b;
                                        if ((f2 >= f3 || fArr[i42] < f3) && (fArr[i42] >= f3 || f2 < f3)) {
                                            arrayList2 = arrayList6;
                                        } else {
                                            float[] fArr2 = bVar2.a;
                                            arrayList2 = arrayList6;
                                            float f4 = fArr2[i52];
                                            if (android.support.v4.media.session.a.a(fArr2[i42], f4, (f3 - f2) / (fArr[i42] - f2), f4) < sourceTouch.a) {
                                                z = !z;
                                            }
                                        }
                                        i42 = i52;
                                        i52++;
                                        arrayList6 = arrayList2;
                                    }
                                    arrayList = arrayList6;
                                    if (z) {
                                    }
                                }
                                if (i22 != size) {
                                    i22++;
                                    arrayList6 = arrayList;
                                }
                            }
                            i22 = -1;
                        } else {
                            i22 = -1;
                        }
                        if (i22 >= 0) {
                            treeSet.add(Integer.valueOf(i22));
                            aVar3.d.b(Integer.valueOf(i22));
                            aVar3.c.add(Integer.valueOf(i22));
                            return;
                        }
                        return;
                }
            }
        };
        dVar6.getClass();
        io.reactivex.rxjava3.internal.operators.observable.C c3 = new io.reactivex.rxjava3.internal.operators.observable.C(dVar6, dVar7, bVar);
        final int i6 = 5;
        c3.u(new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.o
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i22;
                ArrayList arrayList;
                ArrayList arrayList2;
                switch (i6) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        this.b.G(p0);
                        return;
                    case 1:
                        Unit it2 = (Unit) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE02 = scanDocumentFragment.e0();
                        String term = scanDocumentFragment.X();
                        String definition = scanDocumentFragment.W();
                        hVarE02.getClass();
                        Intrinsics.checkNotNullParameter(term, "term");
                        Intrinsics.checkNotNullParameter(definition, "definition");
                        hVarE02.f.a.y(hVarE02.e.b.size() + hVarE02.n);
                        hVarE02.H(term, definition);
                        Y y = hVarE02.l;
                        Integer num = (Integer) y.d();
                        y.l(Integer.valueOf((num != null ? num.intValue() : 1) + 1));
                        scanDocumentFragment.d0().getOcrImageView().a();
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE03 = scanDocumentFragment.e0();
                        com.quizlet.scandocument.a aVar2 = hVarE03.e;
                        hVarE03.n = aVar2.b.size();
                        aVar2.b.clear();
                        OcrCardView ocrCardViewV2 = scanDocumentFragment.V();
                        ocrCardViewV2.getClass();
                        C1404g c1404g = new C1404g(1);
                        c1404g.c = 350L;
                        ArrayList arrayList3 = c1404g.f;
                        CardView cardView = ocrCardViewV2.d;
                        arrayList3.add(cardView);
                        Intrinsics.checkNotNullExpressionValue(c1404g, "addTarget(...)");
                        androidx.transition.r rVar = new androidx.transition.r();
                        rVar.H = androidx.transition.r.K;
                        rVar.v = new C1411n();
                        rVar.b = 150L;
                        rVar.c = 350L;
                        rVar.d = new AnticipateOvershootInterpolator();
                        ArrayList arrayList4 = rVar.f;
                        ImageView imageView = ocrCardViewV2.e;
                        arrayList4.add(imageView);
                        ArrayList arrayList5 = rVar.f;
                        QTextView qTextView = ocrCardViewV2.f;
                        arrayList5.add(qTextView);
                        rVar.b(new D(ocrCardViewV2, 1));
                        Intrinsics.checkNotNullExpressionValue(rVar, "addListener(...)");
                        F f = new F();
                        f.R(c1404g);
                        f.R(rVar);
                        f.T(0);
                        C.a(ocrCardViewV2.g, f);
                        cardView.setVisibility(0);
                        imageView.setVisibility(0);
                        qTextView.setVisibility(0);
                        cardView.setVisibility(0);
                        OcrCardView ocrCardViewV3 = scanDocumentFragment.V();
                        QFormField qFormField = ocrCardViewV3.a;
                        Editable text = qFormField.getEditText().getText();
                        if (text != null) {
                            text.clear();
                        }
                        Editable text2 = ocrCardViewV3.b.getEditText().getText();
                        if (text2 != null) {
                            text2.clear();
                        }
                        Intrinsics.checkNotNullParameter(qFormField, "<this>");
                        qFormField.requestFocus();
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 1, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        return;
                    case 2:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        this.b.G(p02);
                        return;
                    case 3:
                        EnumC4781a inputMethod = (EnumC4781a) obj;
                        Intrinsics.checkNotNullParameter(inputMethod, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE04 = this.b.e0();
                        hVarE04.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar = hVarE04.f;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        int iOrdinal = inputMethod.ordinal();
                        EventLogger eventLogger = cVar.a;
                        if (iOrdinal == 0) {
                            eventLogger.z("ocr_tap_ocr");
                        } else {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger.z("ocr_tap_keyboard");
                        }
                        hVarE04.j.l(inputMethod);
                        return;
                    case 4:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        this.b.G(p03);
                        return;
                    case 5:
                        com.quizlet.scandocument.model.b interactionMode = (com.quizlet.scandocument.model.b) obj;
                        Intrinsics.checkNotNullParameter(interactionMode, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE05 = this.b.e0();
                        hVarE05.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar2 = hVarE05.f;
                        cVar2.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        int iOrdinal2 = interactionMode.ordinal();
                        EventLogger eventLogger2 = cVar2.a;
                        if (iOrdinal2 == 0) {
                            eventLogger2.z("ocr_tap_select_mode");
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger2.z("ocr_tap_move_mode");
                        }
                        hVarE05.k.l(interactionMode);
                        return;
                    case 6:
                        io.reactivex.rxjava3.disposables.b p04 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p04, "p0");
                        this.b.G(p04);
                        return;
                    default:
                        PointF touchEvent = (PointF) obj;
                        Intrinsics.checkNotNullParameter(touchEvent, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE06 = this.b.e0();
                        hVarE06.getClass();
                        Intrinsics.checkNotNullParameter(touchEvent, "touchEvent");
                        Intrinsics.checkNotNullParameter(touchEvent, "<this>");
                        com.quizlet.scandocument.graphics.a sourceTouch = new com.quizlet.scandocument.graphics.a(touchEvent.x, touchEvent.y);
                        com.quizlet.scandocument.a aVar3 = hVarE06.e;
                        aVar3.getClass();
                        Intrinsics.checkNotNullParameter(sourceTouch, "sourceTouch");
                        ArrayList arrayList6 = aVar3.a;
                        int size = arrayList6.size() - 1;
                        TreeSet treeSet = aVar3.b;
                        if (size >= 0) {
                            i22 = 0;
                            while (true) {
                                if (treeSet.contains(Integer.valueOf(i22))) {
                                    arrayList = arrayList6;
                                } else {
                                    com.quizlet.scandocument.graphics.b bVar2 = (com.quizlet.scandocument.graphics.b) arrayList6.get(i22);
                                    int i32 = bVar2.c;
                                    int i42 = i32 - 1;
                                    int i52 = 0;
                                    boolean z = false;
                                    while (i52 < i32) {
                                        float[] fArr = bVar2.b;
                                        float f2 = fArr[i52];
                                        float f3 = sourceTouch.b;
                                        if ((f2 >= f3 || fArr[i42] < f3) && (fArr[i42] >= f3 || f2 < f3)) {
                                            arrayList2 = arrayList6;
                                        } else {
                                            float[] fArr2 = bVar2.a;
                                            arrayList2 = arrayList6;
                                            float f4 = fArr2[i52];
                                            if (android.support.v4.media.session.a.a(fArr2[i42], f4, (f3 - f2) / (fArr[i42] - f2), f4) < sourceTouch.a) {
                                                z = !z;
                                            }
                                        }
                                        i42 = i52;
                                        i52++;
                                        arrayList6 = arrayList2;
                                    }
                                    arrayList = arrayList6;
                                    if (z) {
                                    }
                                }
                                if (i22 != size) {
                                    i22++;
                                    arrayList6 = arrayList;
                                }
                            }
                            i22 = -1;
                        } else {
                            i22 = -1;
                        }
                        if (i22 >= 0) {
                            treeSet.add(Integer.valueOf(i22));
                            aVar3.d.b(Integer.valueOf(i22));
                            aVar3.c.add(Integer.valueOf(i22));
                            return;
                        }
                        return;
                }
            }
        }, gVar, bVar);
        io.reactivex.rxjava3.subjects.d dVar8 = d0().getOcrImageView().n;
        final int i7 = 6;
        io.reactivex.rxjava3.functions.d dVar9 = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.o
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i22;
                ArrayList arrayList;
                ArrayList arrayList2;
                switch (i7) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        this.b.G(p0);
                        return;
                    case 1:
                        Unit it2 = (Unit) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE02 = scanDocumentFragment.e0();
                        String term = scanDocumentFragment.X();
                        String definition = scanDocumentFragment.W();
                        hVarE02.getClass();
                        Intrinsics.checkNotNullParameter(term, "term");
                        Intrinsics.checkNotNullParameter(definition, "definition");
                        hVarE02.f.a.y(hVarE02.e.b.size() + hVarE02.n);
                        hVarE02.H(term, definition);
                        Y y = hVarE02.l;
                        Integer num = (Integer) y.d();
                        y.l(Integer.valueOf((num != null ? num.intValue() : 1) + 1));
                        scanDocumentFragment.d0().getOcrImageView().a();
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE03 = scanDocumentFragment.e0();
                        com.quizlet.scandocument.a aVar2 = hVarE03.e;
                        hVarE03.n = aVar2.b.size();
                        aVar2.b.clear();
                        OcrCardView ocrCardViewV2 = scanDocumentFragment.V();
                        ocrCardViewV2.getClass();
                        C1404g c1404g = new C1404g(1);
                        c1404g.c = 350L;
                        ArrayList arrayList3 = c1404g.f;
                        CardView cardView = ocrCardViewV2.d;
                        arrayList3.add(cardView);
                        Intrinsics.checkNotNullExpressionValue(c1404g, "addTarget(...)");
                        androidx.transition.r rVar = new androidx.transition.r();
                        rVar.H = androidx.transition.r.K;
                        rVar.v = new C1411n();
                        rVar.b = 150L;
                        rVar.c = 350L;
                        rVar.d = new AnticipateOvershootInterpolator();
                        ArrayList arrayList4 = rVar.f;
                        ImageView imageView = ocrCardViewV2.e;
                        arrayList4.add(imageView);
                        ArrayList arrayList5 = rVar.f;
                        QTextView qTextView = ocrCardViewV2.f;
                        arrayList5.add(qTextView);
                        rVar.b(new D(ocrCardViewV2, 1));
                        Intrinsics.checkNotNullExpressionValue(rVar, "addListener(...)");
                        F f = new F();
                        f.R(c1404g);
                        f.R(rVar);
                        f.T(0);
                        C.a(ocrCardViewV2.g, f);
                        cardView.setVisibility(0);
                        imageView.setVisibility(0);
                        qTextView.setVisibility(0);
                        cardView.setVisibility(0);
                        OcrCardView ocrCardViewV3 = scanDocumentFragment.V();
                        QFormField qFormField = ocrCardViewV3.a;
                        Editable text = qFormField.getEditText().getText();
                        if (text != null) {
                            text.clear();
                        }
                        Editable text2 = ocrCardViewV3.b.getEditText().getText();
                        if (text2 != null) {
                            text2.clear();
                        }
                        Intrinsics.checkNotNullParameter(qFormField, "<this>");
                        qFormField.requestFocus();
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 1, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        return;
                    case 2:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        this.b.G(p02);
                        return;
                    case 3:
                        EnumC4781a inputMethod = (EnumC4781a) obj;
                        Intrinsics.checkNotNullParameter(inputMethod, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE04 = this.b.e0();
                        hVarE04.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar = hVarE04.f;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        int iOrdinal = inputMethod.ordinal();
                        EventLogger eventLogger = cVar.a;
                        if (iOrdinal == 0) {
                            eventLogger.z("ocr_tap_ocr");
                        } else {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger.z("ocr_tap_keyboard");
                        }
                        hVarE04.j.l(inputMethod);
                        return;
                    case 4:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        this.b.G(p03);
                        return;
                    case 5:
                        com.quizlet.scandocument.model.b interactionMode = (com.quizlet.scandocument.model.b) obj;
                        Intrinsics.checkNotNullParameter(interactionMode, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE05 = this.b.e0();
                        hVarE05.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar2 = hVarE05.f;
                        cVar2.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        int iOrdinal2 = interactionMode.ordinal();
                        EventLogger eventLogger2 = cVar2.a;
                        if (iOrdinal2 == 0) {
                            eventLogger2.z("ocr_tap_select_mode");
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger2.z("ocr_tap_move_mode");
                        }
                        hVarE05.k.l(interactionMode);
                        return;
                    case 6:
                        io.reactivex.rxjava3.disposables.b p04 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p04, "p0");
                        this.b.G(p04);
                        return;
                    default:
                        PointF touchEvent = (PointF) obj;
                        Intrinsics.checkNotNullParameter(touchEvent, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE06 = this.b.e0();
                        hVarE06.getClass();
                        Intrinsics.checkNotNullParameter(touchEvent, "touchEvent");
                        Intrinsics.checkNotNullParameter(touchEvent, "<this>");
                        com.quizlet.scandocument.graphics.a sourceTouch = new com.quizlet.scandocument.graphics.a(touchEvent.x, touchEvent.y);
                        com.quizlet.scandocument.a aVar3 = hVarE06.e;
                        aVar3.getClass();
                        Intrinsics.checkNotNullParameter(sourceTouch, "sourceTouch");
                        ArrayList arrayList6 = aVar3.a;
                        int size = arrayList6.size() - 1;
                        TreeSet treeSet = aVar3.b;
                        if (size >= 0) {
                            i22 = 0;
                            while (true) {
                                if (treeSet.contains(Integer.valueOf(i22))) {
                                    arrayList = arrayList6;
                                } else {
                                    com.quizlet.scandocument.graphics.b bVar2 = (com.quizlet.scandocument.graphics.b) arrayList6.get(i22);
                                    int i32 = bVar2.c;
                                    int i42 = i32 - 1;
                                    int i52 = 0;
                                    boolean z = false;
                                    while (i52 < i32) {
                                        float[] fArr = bVar2.b;
                                        float f2 = fArr[i52];
                                        float f3 = sourceTouch.b;
                                        if ((f2 >= f3 || fArr[i42] < f3) && (fArr[i42] >= f3 || f2 < f3)) {
                                            arrayList2 = arrayList6;
                                        } else {
                                            float[] fArr2 = bVar2.a;
                                            arrayList2 = arrayList6;
                                            float f4 = fArr2[i52];
                                            if (android.support.v4.media.session.a.a(fArr2[i42], f4, (f3 - f2) / (fArr[i42] - f2), f4) < sourceTouch.a) {
                                                z = !z;
                                            }
                                        }
                                        i42 = i52;
                                        i52++;
                                        arrayList6 = arrayList2;
                                    }
                                    arrayList = arrayList6;
                                    if (z) {
                                    }
                                }
                                if (i22 != size) {
                                    i22++;
                                    arrayList6 = arrayList;
                                }
                            }
                            i22 = -1;
                        } else {
                            i22 = -1;
                        }
                        if (i22 >= 0) {
                            treeSet.add(Integer.valueOf(i22));
                            aVar3.d.b(Integer.valueOf(i22));
                            aVar3.c.add(Integer.valueOf(i22));
                            return;
                        }
                        return;
                }
            }
        };
        dVar8.getClass();
        io.reactivex.rxjava3.internal.operators.observable.C c4 = new io.reactivex.rxjava3.internal.operators.observable.C(dVar8, dVar9, bVar);
        final int i8 = 7;
        c4.u(new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.o
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i22;
                ArrayList arrayList;
                ArrayList arrayList2;
                switch (i8) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        this.b.G(p0);
                        return;
                    case 1:
                        Unit it2 = (Unit) obj;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE02 = scanDocumentFragment.e0();
                        String term = scanDocumentFragment.X();
                        String definition = scanDocumentFragment.W();
                        hVarE02.getClass();
                        Intrinsics.checkNotNullParameter(term, "term");
                        Intrinsics.checkNotNullParameter(definition, "definition");
                        hVarE02.f.a.y(hVarE02.e.b.size() + hVarE02.n);
                        hVarE02.H(term, definition);
                        Y y = hVarE02.l;
                        Integer num = (Integer) y.d();
                        y.l(Integer.valueOf((num != null ? num.intValue() : 1) + 1));
                        scanDocumentFragment.d0().getOcrImageView().a();
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE03 = scanDocumentFragment.e0();
                        com.quizlet.scandocument.a aVar2 = hVarE03.e;
                        hVarE03.n = aVar2.b.size();
                        aVar2.b.clear();
                        OcrCardView ocrCardViewV2 = scanDocumentFragment.V();
                        ocrCardViewV2.getClass();
                        C1404g c1404g = new C1404g(1);
                        c1404g.c = 350L;
                        ArrayList arrayList3 = c1404g.f;
                        CardView cardView = ocrCardViewV2.d;
                        arrayList3.add(cardView);
                        Intrinsics.checkNotNullExpressionValue(c1404g, "addTarget(...)");
                        androidx.transition.r rVar = new androidx.transition.r();
                        rVar.H = androidx.transition.r.K;
                        rVar.v = new C1411n();
                        rVar.b = 150L;
                        rVar.c = 350L;
                        rVar.d = new AnticipateOvershootInterpolator();
                        ArrayList arrayList4 = rVar.f;
                        ImageView imageView = ocrCardViewV2.e;
                        arrayList4.add(imageView);
                        ArrayList arrayList5 = rVar.f;
                        QTextView qTextView = ocrCardViewV2.f;
                        arrayList5.add(qTextView);
                        rVar.b(new D(ocrCardViewV2, 1));
                        Intrinsics.checkNotNullExpressionValue(rVar, "addListener(...)");
                        F f = new F();
                        f.R(c1404g);
                        f.R(rVar);
                        f.T(0);
                        C.a(ocrCardViewV2.g, f);
                        cardView.setVisibility(0);
                        imageView.setVisibility(0);
                        qTextView.setVisibility(0);
                        cardView.setVisibility(0);
                        OcrCardView ocrCardViewV3 = scanDocumentFragment.V();
                        QFormField qFormField = ocrCardViewV3.a;
                        Editable text = qFormField.getEditText().getText();
                        if (text != null) {
                            text.clear();
                        }
                        Editable text2 = ocrCardViewV3.b.getEditText().getText();
                        if (text2 != null) {
                            text2.clear();
                        }
                        Intrinsics.checkNotNullParameter(qFormField, "<this>");
                        qFormField.requestFocus();
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        qFormField.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 1, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                        return;
                    case 2:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        this.b.G(p02);
                        return;
                    case 3:
                        EnumC4781a inputMethod = (EnumC4781a) obj;
                        Intrinsics.checkNotNullParameter(inputMethod, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE04 = this.b.e0();
                        hVarE04.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar = hVarE04.f;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        int iOrdinal = inputMethod.ordinal();
                        EventLogger eventLogger = cVar.a;
                        if (iOrdinal == 0) {
                            eventLogger.z("ocr_tap_ocr");
                        } else {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger.z("ocr_tap_keyboard");
                        }
                        hVarE04.j.l(inputMethod);
                        return;
                    case 4:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        this.b.G(p03);
                        return;
                    case 5:
                        com.quizlet.scandocument.model.b interactionMode = (com.quizlet.scandocument.model.b) obj;
                        Intrinsics.checkNotNullParameter(interactionMode, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE05 = this.b.e0();
                        hVarE05.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar2 = hVarE05.f;
                        cVar2.getClass();
                        Intrinsics.checkNotNullParameter(interactionMode, "interactionMode");
                        int iOrdinal2 = interactionMode.ordinal();
                        EventLogger eventLogger2 = cVar2.a;
                        if (iOrdinal2 == 0) {
                            eventLogger2.z("ocr_tap_select_mode");
                        } else {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            eventLogger2.z("ocr_tap_move_mode");
                        }
                        hVarE05.k.l(interactionMode);
                        return;
                    case 6:
                        io.reactivex.rxjava3.disposables.b p04 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p04, "p0");
                        this.b.G(p04);
                        return;
                    default:
                        PointF touchEvent = (PointF) obj;
                        Intrinsics.checkNotNullParameter(touchEvent, "it");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE06 = this.b.e0();
                        hVarE06.getClass();
                        Intrinsics.checkNotNullParameter(touchEvent, "touchEvent");
                        Intrinsics.checkNotNullParameter(touchEvent, "<this>");
                        com.quizlet.scandocument.graphics.a sourceTouch = new com.quizlet.scandocument.graphics.a(touchEvent.x, touchEvent.y);
                        com.quizlet.scandocument.a aVar3 = hVarE06.e;
                        aVar3.getClass();
                        Intrinsics.checkNotNullParameter(sourceTouch, "sourceTouch");
                        ArrayList arrayList6 = aVar3.a;
                        int size = arrayList6.size() - 1;
                        TreeSet treeSet = aVar3.b;
                        if (size >= 0) {
                            i22 = 0;
                            while (true) {
                                if (treeSet.contains(Integer.valueOf(i22))) {
                                    arrayList = arrayList6;
                                } else {
                                    com.quizlet.scandocument.graphics.b bVar2 = (com.quizlet.scandocument.graphics.b) arrayList6.get(i22);
                                    int i32 = bVar2.c;
                                    int i42 = i32 - 1;
                                    int i52 = 0;
                                    boolean z = false;
                                    while (i52 < i32) {
                                        float[] fArr = bVar2.b;
                                        float f2 = fArr[i52];
                                        float f3 = sourceTouch.b;
                                        if ((f2 >= f3 || fArr[i42] < f3) && (fArr[i42] >= f3 || f2 < f3)) {
                                            arrayList2 = arrayList6;
                                        } else {
                                            float[] fArr2 = bVar2.a;
                                            arrayList2 = arrayList6;
                                            float f4 = fArr2[i52];
                                            if (android.support.v4.media.session.a.a(fArr2[i42], f4, (f3 - f2) / (fArr[i42] - f2), f4) < sourceTouch.a) {
                                                z = !z;
                                            }
                                        }
                                        i42 = i52;
                                        i52++;
                                        arrayList6 = arrayList2;
                                    }
                                    arrayList = arrayList6;
                                    if (z) {
                                    }
                                }
                                if (i22 != size) {
                                    i22++;
                                    arrayList6 = arrayList;
                                }
                            }
                            i22 = -1;
                        } else {
                            i22 = -1;
                        }
                        if (i22 >= 0) {
                            treeSet.add(Integer.valueOf(i22));
                            aVar3.d.b(Integer.valueOf(i22));
                            aVar3.c.add(Integer.valueOf(i22));
                            return;
                        }
                        return;
                }
            }
        }, gVar, bVar);
        final int i9 = 0;
        d0().getScanDocumentCtaButton().setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.n
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i9) {
                    case 0:
                        this.b.g0();
                        break;
                    case 1:
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        Toast.makeText(scanDocumentFragment.requireContext(), "Congrats, you are ready", 0).show();
                        scanDocumentFragment.d0().getOnboardingView().setVisibility(8);
                        break;
                    default:
                        this.b.g0();
                        break;
                }
            }
        });
        final int i10 = 1;
        d0().getOnboardingView().setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.n
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i10) {
                    case 0:
                        this.b.g0();
                        break;
                    case 1:
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        Toast.makeText(scanDocumentFragment.requireContext(), "Congrats, you are ready", 0).show();
                        scanDocumentFragment.d0().getOnboardingView().setVisibility(8);
                        break;
                    default:
                        this.b.g0();
                        break;
                }
            }
        });
        final int i11 = 2;
        d0().getChangeImageButton().setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.fragments.n
            public final /* synthetic */ ScanDocumentFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i11) {
                    case 0:
                        this.b.g0();
                        break;
                    case 1:
                        ScanDocumentFragment scanDocumentFragment = this.b;
                        Toast.makeText(scanDocumentFragment.requireContext(), "Congrats, you are ready", 0).show();
                        scanDocumentFragment.d0().getOnboardingView().setVisibility(8);
                        break;
                    default:
                        this.b.g0();
                        break;
                }
            }
        });
        this.p = new com.quizlet.quizletandroid.sessionhelpers.a("NEW", requireActivity().getIntent());
        androidx.lifecycle.C lifecycle = getLifecycle();
        com.quizlet.quizletandroid.sessionhelpers.a aVar2 = this.p;
        if (aVar2 == null) {
            Intrinsics.m("editTracker");
            throw null;
        }
        lifecycle.a(aVar2);
        com.quizlet.quizletandroid.sessionhelpers.a aVar3 = this.p;
        if (aVar3 == null) {
            Intrinsics.m("editTracker");
            throw null;
        }
        aVar3.h(bundle);
        OcrImageView ocrImageView = d0().getOcrImageView();
        TreeSet selectedIndexes = e0().e.b;
        TreeSet visitedIndexes = e0().e.c;
        ocrImageView.getClass();
        Intrinsics.checkNotNullParameter(selectedIndexes, "selectedIndexes");
        Intrinsics.checkNotNullParameter(visitedIndexes, "visitedIndexes");
        ocrImageView.o = selectedIndexes;
        ocrImageView.p = visitedIndexes;
        ocrImageView.invalidate();
        if (bundle != null) {
            a0().M(bundle);
        }
        getChildFragmentManager().h0("ADD_IMAGE_REQUEST_KEY", getViewLifecycleOwner(), this);
    }

    @Override // androidx.fragment.app.m0
    public final void y(Bundle result, String requestKey) {
        Intrinsics.checkNotNullParameter(requestKey, "requestKey");
        Intrinsics.checkNotNullParameter(result, "result");
        if (!requestKey.equals("ADD_IMAGE_REQUEST_KEY")) {
            timber.log.c.a.e(new IllegalArgumentException(android.support.v4.media.session.a.B("Request key ", requestKey, " is not supported. Supported options are: ADD_IMAGE_REQUEST_KEY")));
            return;
        }
        Object obj = result.get("ADD_IMAGE_RESULT_KEY");
        Intrinsics.e(obj, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.setpage.AddImageBottomSheet.Method");
        int iOrdinal = ((com.quizlet.quizletandroid.ui.setpage.a) obj).ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            Y().a.z("ocr_select_image_gallery");
            androidx.activity.result.b bVar = this.q;
            if (bVar != null) {
                H6.d(bVar);
                return;
            } else {
                Intrinsics.m("mediaRequest");
                throw null;
            }
        }
        Y().a.z("ocr_select_image_camera");
        if (androidx.core.content.c.a(requireContext(), "android.permission.CAMERA") == 0) {
            a0().F(this, false);
            return;
        }
        androidx.camera.camera2.internal.compat.workaround.e eVar = this.l;
        if (eVar != null) {
            eVar.p(this);
        } else {
            Intrinsics.m("permissionsManager");
            throw null;
        }
    }
}
