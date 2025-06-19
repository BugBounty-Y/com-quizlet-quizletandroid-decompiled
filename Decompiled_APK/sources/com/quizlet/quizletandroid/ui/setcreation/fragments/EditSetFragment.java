package com.quizlet.quizletandroid.ui.setcreation.fragments;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcelable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import androidx.appcompat.app.K;
import androidx.camera.camera2.internal.C0128e;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.I;
import androidx.fragment.app.m0;
import androidx.recyclerview.widget.C1397z;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.ads.C2824xF;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.H6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.generated.enums.O1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4619x;
import com.quizlet.quizletandroid.ui.globalnav.composable.s;
import com.quizlet.quizletandroid.ui.setcreation.activities.ScanDocumentActivity;
import com.quizlet.quizletandroid.ui.setcreation.managers.CardFocusPosition;
import com.quizlet.richtext.ui.toolbar.QRichTextToolbar;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.views.SimpleGradientView;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.internal.operators.observable.C;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.C4896o;
import io.reactivex.rxjava3.subjects.r;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class EditSetFragment extends Hilt_EditSetFragment<C4619x> implements com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a, m0 {
    public static final String J;
    public static final String K;
    public com.quizlet.quizletandroid.ui.setcreation.adapters.f A;
    public androidx.core.util.c B;
    public com.quizlet.quizletandroid.ui.setcreation.adapters.f C;
    public com.quizlet.quizletandroid.ui.login.h D;
    public K E;
    public final u F;
    public CardFocusPosition G;
    public C0128e H;
    public androidx.activity.result.b I;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j;
    public com.quizlet.infra.legacysyncengine.managers.d k;
    public androidx.work.impl.model.c l;
    public io.reactivex.rxjava3.core.o m;
    public com.quizlet.quizletandroid.util.f n;
    public com.quizlet.qutils.image.loading.a o;
    public com.quizlet.quizletandroid.ui.setcreation.tracking.c p;
    public androidx.camera.camera2.internal.compat.workaround.e q;
    public com.google.android.gms.internal.appset.e r;
    public com.quizlet.data.repository.explanations.question.a s;
    public C2824xF t;
    public com.quizlet.quizletandroid.ui.common.images.capture.c u;
    public com.quizlet.richtext.rendering.c v;
    public com.quizlet.quizletandroid.ui.setcreation.managers.n w;
    public WeakReference x;
    public EditSetFragment$initView$1 y;
    public Parcelable z;

    static {
        Intrinsics.checkNotNullExpressionValue("EditSetFragment", "getSimpleName(...)");
        J = "EditSetFragment";
        K = "EditSetFragment";
    }

    public EditSetFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new com.quizlet.login.recovery.forgotpassword.ui.e(this, 17), 18));
        this.j = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.quizletandroid.ui.setcreation.viewmodels.e.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 23), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 9), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 24));
        this.F = kotlin.l.b(new c(this, 2));
        this.G = new CardFocusPosition(-1, -1, null);
    }

    public static final void T(EditSetFragment editSetFragment, com.quizlet.features.infra.models.upgrade.a aVar) throws Exception {
        int i;
        String str;
        com.quizlet.infra.legacysyncengine.managers.d dVar = editSetFragment.k;
        if (dVar == null) {
            Intrinsics.m("loggedInUserManager");
            throw null;
        }
        if (dVar.r != null) {
            if (aVar == com.quizlet.features.infra.models.upgrade.a.l) {
                i = 224;
                str = "create_setocr";
            } else {
                i = 0;
                str = K;
            }
            String str2 = UpgradeActivity.v;
            Context contextRequireContext = editSetFragment.requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
            Intent intentI = AbstractC3242q6.i(contextRequireContext, str, aVar);
            if (i > 0) {
                editSetFragment.startActivityForResult(intentI, i);
            } else {
                editSetFragment.startActivity(intentI);
            }
        }
    }

    public static final void U(EditSetFragment editSetFragment, String str, String str2, String str3, String str4, long j) {
        e.a aVar = new e.a(editSetFragment.getContext());
        if (str != null) {
            aVar.d = str;
        }
        aVar.e = str2;
        C0128e c0128e = new C0128e(editSetFragment, j, 3);
        aVar.i = str3;
        aVar.j = c0128e;
        aVar.k = str4;
        aVar.l = null;
        aVar.b().show();
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return J;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_edit_set, viewGroup, false);
        int i = R.id.bottom_fading_edge;
        if (((SimpleGradientView) AbstractC3375o2.c(R.id.bottom_fading_edge, viewInflate)) != null) {
            i = R.id.edit_set_term_list;
            RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.edit_set_term_list, viewInflate);
            if (recyclerView != null) {
                i = R.id.rt_toolbar;
                QRichTextToolbar qRichTextToolbar = (QRichTextToolbar) AbstractC3375o2.c(R.id.rt_toolbar, viewInflate);
                if (qRichTextToolbar != null) {
                    C4619x c4619x = new C4619x((RelativeLayout) viewInflate, recyclerView, qRichTextToolbar);
                    Intrinsics.checkNotNullExpressionValue(c4619x, "inflate(...)");
                    return c4619x;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void V() {
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = this.A;
        if (fVar != null) {
            fVar.m();
            ArrayList arrayList = fVar.p;
            if (arrayList == null) {
                return;
            }
            fVar.d(arrayList.size());
            if (fVar.k() != null) {
                fVar.k().e("add_term");
            }
        }
    }

    public final void W(int i, O1 portion) {
        ArrayList arrayList;
        Intrinsics.checkNotNullParameter(portion, "portion");
        this.B = new androidx.core.util.c(portion, new f(this, i, portion));
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = this.A;
        List listUnmodifiableList = (fVar == null || (arrayList = fVar.p) == null) ? null : Collections.unmodifiableList(arrayList);
        if (listUnmodifiableList != null && listUnmodifiableList.size() > 0 && listUnmodifiableList.size() < i && portion == O1.WORD) {
            V();
        }
        EditSetFragment$initView$1 editSetFragment$initView$1 = this.y;
        if (editSetFragment$initView$1 != null) {
            editSetFragment$initView$1.F0(a0(), null, i);
        }
    }

    public final void X(boolean z) {
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = this.A;
        if (fVar != null) {
            fVar.f = z;
            fVar.notifyItemChanged(fVar.getItemCount() - 1, Integer.valueOf(z ? 1000 : com.pubmatic.sdk.video.a.UNDEFINED_ERROR));
        }
    }

    public final C2824xF Y() {
        C2824xF c2824xF = this.t;
        if (c2824xF != null) {
            return c2824xF;
        }
        Intrinsics.m("imageCapturerManager");
        throw null;
    }

    public final RecyclerView a0() {
        RecyclerView editSetTermList = ((C4619x) J()).b;
        Intrinsics.checkNotNullExpressionValue(editSetTermList, "editSetTermList");
        return editSetTermList;
    }

    public final QRichTextToolbar b0() {
        QRichTextToolbar rtToolbar = ((C4619x) J()).c;
        Intrinsics.checkNotNullExpressionValue(rtToolbar, "rtToolbar");
        return rtToolbar;
    }

    public final com.quizlet.quizletandroid.ui.setcreation.viewmodels.e c0() {
        return (com.quizlet.quizletandroid.ui.setcreation.viewmodels.e) this.j.getValue();
    }

    public final void d0(DBTerm term) {
        com.quizlet.quizletandroid.sessionhelpers.a aVar;
        Intrinsics.checkNotNullParameter(term, "term");
        WeakReference weakReference = this.x;
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar = weakReference != null ? (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get() : null;
        if (bVar != null && (aVar = ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).m) != null) {
            Long lValueOf = Long.valueOf(term.getLocalId());
            Long lValueOf2 = Long.valueOf(term.getId());
            aVar.g();
            aVar.a("add_image", lValueOf, lValueOf2).d();
        }
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = this.A;
        if (fVar != null) {
            fVar.m();
        }
    }

    public final void e0() {
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
        DBStudySet dBStudySet;
        WeakReference weakReference = this.x;
        if (weakReference == null || (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) == null || (dBStudySet = ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).y.m) == null) {
            return;
        }
        long id = dBStudySet.getId();
        int i = ScanDocumentActivity.o;
        Context context = requireContext();
        Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
        Intrinsics.checkNotNullParameter(context, "context");
        Intent intent = new Intent(context, (Class<?>) ScanDocumentActivity.class);
        intent.putExtra("setId", id);
        startActivity(intent);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:27:0x004e  */
    /* JADX WARN: Type inference failed for: r26v0 */
    /* JADX WARN: Type inference failed for: r26v1 */
    /* JADX WARN: Type inference failed for: r26v2 */
    /* JADX WARN: Type inference failed for: r26v3 */
    /* JADX WARN: Type inference failed for: r26v4 */
    /* JADX WARN: Type inference failed for: r26v5 */
    /* JADX WARN: Type inference failed for: r26v6 */
    /* JADX WARN: Type inference failed for: r7v3, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    /* JADX WARN: Type inference failed for: r7v4, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f0(com.quizlet.db.data.models.persisted.DBTerm r32, com.quizlet.quizletandroid.ui.setcreation.activities.a r33, com.quizlet.quizletandroid.ui.setcreation.activities.a r34) {
        /*
            Method dump skipped, instructions count: 702
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment.f0(com.quizlet.db.data.models.persisted.DBTerm, com.quizlet.quizletandroid.ui.setcreation.activities.a, com.quizlet.quizletandroid.ui.setcreation.activities.a):void");
    }

    public final void g0(O1 termSide, String languageName) {
        Intrinsics.checkNotNullParameter(termSide, "termSide");
        Intrinsics.checkNotNullParameter(languageName, "languageName");
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = this.A;
        if (fVar != null) {
            fVar.n(termSide, languageName);
        }
    }

    public final void h0() {
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar;
        WeakReference weakReference = this.x;
        if (weakReference == null || (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) == null || (fVar = this.A) == null) {
            return;
        }
        ArrayList arrayList = fVar.p;
        List listUnmodifiableList = arrayList == null ? null : Collections.unmodifiableList(arrayList);
        if (listUnmodifiableList == null) {
            return;
        }
        int size = listUnmodifiableList.size();
        int iMin = Math.min(this.G.a + 1, size);
        if (this.G.a != -1) {
            bVar.setTitle(getString(R.string.edit_set_position, Integer.valueOf(iMin), Integer.valueOf(size)));
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onActivityResult(int i, int i2, Intent intent) {
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
        super.onActivityResult(i, i2, intent);
        WeakReference weakReference = this.x;
        if (weakReference == null || (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) == null || i2 != -1) {
            return;
        }
        if (i == 100) {
            com.quizlet.quizletandroid.ui.setcreation.activities.d dVar = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar;
            dVar.x(dVar.y.o.i(new com.quizlet.quizletandroid.ui.setcreation.activities.b(dVar, 1), io.reactivex.rxjava3.internal.functions.d.e));
            return;
        }
        if (i == 101) {
            c0().C();
            return;
        }
        if (i != 224) {
            if (i != 1000) {
                return;
            }
            C2824xF c2824xFY = Y();
            ((androidx.camera.camera2.internal.concurrent.a) c2824xFY.c).D(i, i2, (Context) ((WeakReference) c2824xFY.e).get(), new com.quizlet.quizletandroid.ui.activitycenter.views.i(c2824xFY, 2));
            return;
        }
        Integer numValueOf = intent != null ? Integer.valueOf(intent.getIntExtra("ResultUserUpgradeType", 0)) : null;
        if ((numValueOf != null && numValueOf.intValue() == 1) || (numValueOf != null && numValueOf.intValue() == 2)) {
            e0();
        }
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.fragments.Hilt_EditSetFragment, com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        super.onAttach(context);
        Y().d = this;
        Y().e = new WeakReference(context);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        C2824xF c2824xFY = Y();
        if (bundle != null) {
            c2824xFY.a = bundle.getLong("CreateSetImageCapturerManager_savedCurrentTermId");
            ((androidx.camera.camera2.internal.concurrent.a) c2824xFY.c).M(bundle);
        }
        WeakReference weakReference = this.x;
        if (weakReference == null || ((com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) == null) {
            return;
        }
        this.D = new com.quizlet.quizletandroid.ui.login.h(this, 1);
        this.E = new K(16);
        androidx.activity.result.b bVarG = H6.g(this, new a(this, 4));
        Intrinsics.checkNotNullParameter(bVarG, "<set-?>");
        this.I = bVarG;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        io.reactivex.rxjava3.subjects.d dVar;
        int i = 4;
        int i2 = 0;
        int i3 = 18;
        int i4 = 3;
        int i5 = 1;
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewOnCreateView = super.onCreateView(inflater, viewGroup, bundle);
        WeakReference weakReference = this.x;
        if (weakReference == null || ((com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) == null) {
            return null;
        }
        C4619x c4619x = (C4619x) J();
        com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, i3);
        WeakHashMap weakHashMap = V.a;
        L.m(c4619x.a, bVar);
        QRichTextToolbar qRichTextToolbarB0 = b0();
        com.quizlet.quizletandroid.ui.setcreation.managers.n nVar = this.w;
        if (nVar == null) {
            Intrinsics.m("highlightColorResolver");
            throw null;
        }
        qRichTextToolbarB0.setHighlightColorResolver(nVar);
        qRichTextToolbarB0.setToolbarActionClickListener(new s(1, c0(), com.quizlet.quizletandroid.ui.setcreation.viewmodels.e.class, "onRichTextActionClicked", "onRichTextActionClicked(Lorg/wordpress/aztec/toolbar/IToolbarAction;)V", 0, 23));
        io.reactivex.rxjava3.core.o oVar = this.m;
        if (oVar == null) {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
        com.quizlet.qutils.image.loading.a aVar = this.o;
        if (aVar == null) {
            Intrinsics.m("imageLoader");
            throw null;
        }
        com.quizlet.data.repository.explanations.question.a aVar2 = this.s;
        if (aVar2 == null) {
            Intrinsics.m("imageUploadFeatureWrapper");
            throw null;
        }
        io.reactivex.rxjava3.subjects.d dVar2 = ((com.quizlet.infra.legacysyncengine.managers.d) aVar2.d).l;
        dVar2.getClass();
        C4887f c4887f = new C4887f(dVar2, i5);
        assistantMode.utils.studiableMetadata.b bVar2 = (assistantMode.utils.studiableMetadata.b) aVar2.a;
        androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) aVar2.c;
        io.reactivex.rxjava3.core.i iVarM = bVar2.L(cVar).m();
        io.reactivex.rxjava3.core.i iVarM2 = ((com.google.android.material.floatingactionbutton.c) aVar2.b).o(cVar).m();
        com.quizlet.quizletandroid.k kVar = new com.quizlet.quizletandroid.k(new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(i2), i3);
        int i6 = io.reactivex.rxjava3.core.e.a;
        io.reactivex.rxjava3.internal.functions.d.a(i6, "bufferSize");
        C4896o c4896o = new C4896o(new io.reactivex.rxjava3.core.k[]{c4887f, iVarM, iVarM2}, kVar, i6, i5);
        Intrinsics.checkNotNullExpressionValue(c4896o, "zip(...)");
        com.google.android.gms.internal.appset.e eVar = this.r;
        if (eVar == null) {
            Intrinsics.m("scanDocumentManager");
            throw null;
        }
        com.quizlet.quizletandroid.ui.login.h hVar = this.D;
        K k = this.E;
        com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar2 = this.p;
        if (cVar2 == null) {
            Intrinsics.m("scanDocumentEventLogger");
            throw null;
        }
        QRichTextToolbar qRichTextToolbarB02 = b0();
        com.quizlet.richtext.rendering.c cVar3 = this.v;
        if (cVar3 == null) {
            Intrinsics.m("richTextRenderer");
            throw null;
        }
        androidx.work.impl.model.c cVar4 = this.l;
        if (cVar4 == null) {
            Intrinsics.m("userProps");
            throw null;
        }
        this.A = new com.quizlet.quizletandroid.ui.setcreation.adapters.f(this, oVar, aVar, c4896o, eVar, hVar, k, cVar2, qRichTextToolbarB02, cVar3, cVar4, new com.google.android.material.textfield.a(this, i));
        I activity = requireActivity();
        Intrinsics.checkNotNullExpressionValue(activity, "requireActivity(...)");
        Intrinsics.checkNotNullParameter(activity, "activity");
        C4887f c4887f2 = new C4887f(new com.jakewharton.rxbinding4.a(new com.quizlet.infra.legacysyncengine.tasks.parse.b(activity, 23), i4), i5);
        Intrinsics.checkNotNullExpressionValue(c4887f2, "distinctUntilChanged(...)");
        h hVar2 = new h(this, i4);
        io.reactivex.rxjava3.internal.functions.b bVar3 = io.reactivex.rxjava3.internal.functions.d.c;
        new C(c4887f2, hVar2, bVar3).u(new h(this, i), io.reactivex.rxjava3.internal.functions.d.e, bVar3);
        this.y = new EditSetFragment$initView$1(this, (dagger.hilt.android.internal.managers.j) getContext());
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = this.A;
        this.C = fVar;
        a0().setAdapter(fVar);
        a0().setLayoutManager(this.y);
        com.quizlet.quizletandroid.ui.setcreation.callbacks.b bVar4 = new com.quizlet.quizletandroid.ui.setcreation.callbacks.b();
        bVar4.b = fVar;
        bVar4.a = DefinitionKt.NO_Float_VALUE;
        androidx.recyclerview.widget.L l = new androidx.recyclerview.widget.L(bVar4);
        a0().i(l);
        l.f(a0());
        a0().k(new C1397z(this, 2));
        if (fVar != null && (dVar = fVar.k) != null) {
            new C4887f(new C(dVar, new h(this, i5), bVar3), i5).u(new h(this, 2), new com.quizlet.billing.manager.d(timber.log.c.a, 11), bVar3);
        }
        return viewOnCreateView;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        io.reactivex.rxjava3.internal.observers.h hVar;
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = this.A;
        if (fVar != null && (hVar = fVar.A) != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(hVar);
        }
        this.A = null;
        super.onDestroyView();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDetach() {
        super.onDetach();
        WeakReference weakReference = this.x;
        if (weakReference != null) {
            weakReference.clear();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onRequestPermissionsResult(int i, String[] permissions, int[] grantResults) {
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        Intrinsics.checkNotNullParameter(grantResults, "grantResults");
        androidx.camera.camera2.internal.compat.workaround.e eVar = this.q;
        if (eVar != null) {
            androidx.camera.camera2.internal.compat.workaround.e.l(eVar, this, i, permissions, grantResults, new c(this, 0), new c(this, 1));
        } else {
            Intrinsics.m("permissionsManager");
            throw null;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
        super.onResume();
        WeakReference weakReference = this.x;
        if (weakReference == null || (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) == null) {
            return;
        }
        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).y;
        Intrinsics.checkNotNullExpressionValue(iVar, "getModelManager(...)");
        r rVar = iVar.o;
        h hVar = new h(this, 5);
        rVar.getClass();
        io.reactivex.rxjava3.internal.operators.single.d dVar = new io.reactivex.rxjava3.internal.operators.single.d(rVar, hVar, 1);
        io.reactivex.rxjava3.core.o oVar = this.m;
        if (oVar == null) {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
        io.reactivex.rxjava3.internal.operators.single.k kVarH = dVar.h(oVar);
        com.quizlet.billing.manager.b bVar2 = new com.quizlet.billing.manager.b(15, this, iVar);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
        kVarH.i(bVar2, gVar);
        r rVar2 = iVar.q;
        h hVar2 = new h(this, 6);
        rVar2.getClass();
        io.reactivex.rxjava3.internal.operators.single.d dVar2 = new io.reactivex.rxjava3.internal.operators.single.d(rVar2, hVar2, 1);
        io.reactivex.rxjava3.core.o oVar2 = this.m;
        if (oVar2 != null) {
            dVar2.h(oVar2).i(new h(this, 7), gVar);
        } else {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        EditSetFragment$initView$1 editSetFragment$initView$1 = this.y;
        outState.putParcelable("editSetFragmentLayoutStateKey", editSetFragment$initView$1 != null ? editSetFragment$initView$1.k0() : null);
        outState.putParcelable("editSetFragmentFocusKey", this.G);
        C2824xF c2824xFY = Y();
        DBTerm dBTerm = (DBTerm) c2824xFY.f;
        if (dBTerm != null) {
            outState.putLong("CreateSetImageCapturerManager_savedCurrentTermId", dBTerm.getId());
        }
        ((androidx.camera.camera2.internal.concurrent.a) c2824xFY.c).N(outState);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        Context context = view.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        c0().h.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(15, new a(this, 0)));
        c0().i.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(15, new a(this, 1)));
        c0().l.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(15, new com.quizlet.features.setpage.header.ui.g(17, this, context)));
        c0().o.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(15, new a(this, 2)));
        c0().m.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(15, new s(1, this, EditSetFragment.class, "setRichTextPremiumBadgeState", "setRichTextPremiumBadgeState(Lcom/quizlet/quizletandroid/ui/setcreation/viewmodels/PremiumBadgeState;)V", 0, 22)));
        c0().n.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(15, new a(this, 3)));
        if (((Boolean) this.F.getValue()).booleanValue() && (fVar = this.A) != null) {
            fVar.q = Boolean.FALSE;
            fVar.notifyDataSetChanged();
        }
        getChildFragmentManager().h0("ADD_IMAGE_REQUEST_KEY", getViewLifecycleOwner(), this);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewStateRestored(Bundle bundle) {
        O1 o1;
        View view;
        super.onViewStateRestored(bundle);
        if (bundle != null) {
            Parcelable parcelable = bundle.getParcelable("editSetFragmentLayoutStateKey");
            this.z = parcelable;
            EditSetFragment$initView$1 editSetFragment$initView$1 = this.y;
            if (editSetFragment$initView$1 != null) {
                editSetFragment$initView$1.j0(parcelable);
            }
            CardFocusPosition cardFocusPosition = (CardFocusPosition) bundle.getParcelable("editSetFragmentFocusKey");
            if (cardFocusPosition == null) {
                cardFocusPosition = new CardFocusPosition(-1, -1, null);
            }
            this.G = cardFocusPosition;
            if (cardFocusPosition.b < 0 || (o1 = cardFocusPosition.c) == null || (view = getView()) == null) {
                return;
            }
            view.post(new com.google.firebase.crashlytics.internal.common.i(24, this, o1));
        }
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
        if (iOrdinal == 0) {
            Y().d(this);
            return;
        }
        if (iOrdinal != 1) {
            throw new NoWhenBranchMatchedException();
        }
        androidx.activity.result.b bVar = this.I;
        if (bVar != null) {
            H6.d(bVar);
        } else {
            Intrinsics.m("mediaRequest");
            throw null;
        }
    }
}
