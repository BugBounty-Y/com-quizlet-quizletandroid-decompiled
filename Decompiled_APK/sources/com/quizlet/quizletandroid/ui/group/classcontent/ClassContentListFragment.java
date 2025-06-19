package com.quizlet.quizletandroid.ui.group.classcontent;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.braze.C1510p;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3309z0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.features.folders.FolderActivity;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.login.recovery.forgotpassword.ui.f;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4611o;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.h;
import com.quizlet.quizletandroid.ui.common.views.c;
import com.quizlet.quizletandroid.ui.globalnav.composable.n;
import com.quizlet.quizletandroid.ui.globalnav.composable.s;
import com.quizlet.quizletandroid.ui.group.addclassset.AddClassSetActivity;
import com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.d;
import com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.i;
import com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.j;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.J;
import io.reactivex.rxjava3.internal.operators.single.g;
import io.reactivex.rxjava3.subjects.r;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;

@Metadata
/* loaded from: classes3.dex */
public final class ClassContentListFragment extends Hilt_ClassContentListFragment<C4611o> {
    public static final String n;
    public com.quizlet.offline.managers.b j;
    public final e k;
    public com.quizlet.quizletandroid.ui.group.classcontent.adapter.a l;
    public CardView m;

    static {
        Intrinsics.checkNotNullExpressionValue("ClassContentListFragment", "getSimpleName(...)");
        n = "ClassContentListFragment";
    }

    public ClassContentListFragment() {
        com.quizlet.login.magiclink.ui.e eVar = new com.quizlet.login.magiclink.ui.e(this, 14);
        k kVarA = l.a(m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new com.quizlet.login.recovery.forgotpassword.ui.e(this, 6), 7));
        this.k = new e(K.a(com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a.class), new f(kVarA, 6), new h(this, kVarA, 2), new h(eVar, kVarA, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return n;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.class_content_list_fragment, viewGroup, false);
        int i = R.id.loadingSpinner;
        ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.loadingSpinner, viewInflate);
        if (progressBar != null) {
            i = R.id.recyclerView;
            RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.recyclerView, viewInflate);
            if (recyclerView != null) {
                C4611o c4611o = new C4611o((ConstraintLayout) viewInflate, progressBar, recyclerView);
                Intrinsics.checkNotNullExpressionValue(c4611o, "inflate(...)");
                return c4611o;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final CardView T(View.OnClickListener onClickListener) {
        ConstraintLayout parent = ((C4611o) J()).a;
        Intrinsics.checkNotNullExpressionValue(parent, "getRoot(...)");
        Intrinsics.checkNotNullParameter(parent, "parent");
        Intrinsics.checkNotNullParameter(onClickListener, "onClickListener");
        c[] cVarArr = c.a;
        com.quizlet.features.infra.legacyadapter.databinding.f fVarA = com.quizlet.features.infra.legacyadapter.databinding.f.a(LayoutInflater.from(parent.getContext()).inflate(R.layout.nav2_view_empty_state, (ViewGroup) parent, false));
        Intrinsics.checkNotNullExpressionValue(fVarA, "inflate(...)");
        ((QTextView) fVarA.d).setText(parent.getContext().getText(R.string.nav2_empty_class_header));
        ((QTextView) fVarA.e).setText(parent.getContext().getText(R.string.nav2_empty_class_message));
        ((QButton) fVarA.c).setOnClickListener(onClickListener);
        CardView cardView = (CardView) fVarA.b;
        Intrinsics.checkNotNullExpressionValue(cardView, "getRoot(...)");
        this.m = cardView;
        ((C4611o) J()).a.addView(cardView);
        cardView.setVisibility(0);
        return cardView;
    }

    public final com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a U() {
        return (com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a) this.k.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        U().l.m(this, new n(0, this, ClassContentListFragment.class, "onLoading", "onLoading()V", 0, 3), new s(1, this, ClassContentListFragment.class, "onRender", "onRender(Lcom/quizlet/quizletandroid/ui/group/classcontent/viewmodel/LoadedData;)V", 0, 1));
        final int i = 0;
        U().m.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(9, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.group.classcontent.a
            public final /* synthetic */ ClassContentListFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Exception {
                ClassContentListFragment classContentListFragment = this.b;
                switch (i) {
                    case 0:
                        com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.l lVar = (com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.l) obj;
                        String str = ClassContentListFragment.n;
                        if (lVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.k) {
                            long j = ((com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.k) lVar).a;
                            com.quizlet.features.setpage.e eVar = SetPageActivity.h1;
                            Context contextRequireContext = classContentListFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                            classContentListFragment.startActivityForResult(com.quizlet.features.setpage.e.b(eVar, contextRequireContext, j, null, null, null, null, false, null, 252), 201);
                        } else if (lVar instanceof j) {
                            long j2 = ((j) lVar).a;
                            String str2 = FolderActivity.j;
                            Context contextRequireContext2 = classContentListFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                            classContentListFragment.startActivityForResult(AbstractC3309z0.b(contextRequireContext2, j2), 201);
                        } else {
                            if (!(lVar instanceof i)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            long j3 = ((i) lVar).a;
                            Context context = classContentListFragment.getContext();
                            Long lValueOf = Long.valueOf(j3);
                            int i2 = AddClassSetActivity.w;
                            Intent intent = new Intent(context, (Class<?>) AddClassSetActivity.class);
                            intent.putExtra("current_class_id", lValueOf);
                            classContentListFragment.startActivityForResult(intent, 218);
                        }
                        return Unit.a;
                    default:
                        d dVar = (d) obj;
                        String str3 = ClassContentListFragment.n;
                        if (dVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.c) {
                            com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.c cVar = (com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.c) dVar;
                            long j4 = cVar.a;
                            com.quizlet.offline.managers.b bVar = classContentListFragment.j;
                            if (bVar == null) {
                                Intrinsics.m("offlineStateManager");
                                throw null;
                            }
                            Context contextRequireContext3 = classContentListFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                            com.quizlet.features.setpage.e eVar2 = SetPageActivity.h1;
                            Context contextRequireContext4 = classContentListFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext4, "requireContext(...)");
                            ((com.quizlet.offline.managers.i) bVar).d(contextRequireContext3, cVar.b, com.quizlet.features.setpage.e.b(eVar2, contextRequireContext4, j4, null, null, null, null, false, null, 252), new com.quizlet.infra.legacysyncengine.tasks.parse.b(classContentListFragment, 6));
                        } else {
                            if (!(dVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.uicommon.ui.common.dialogs.l.P(R.string.add_class_under_13_title_dialog, R.string.add_class_under_13_msg_dialog, R.string.got_it).O(classContentListFragment.getChildFragmentManager(), "l");
                        }
                        return Unit.a;
                }
            }
        }));
        final int i2 = 1;
        U().n.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(9, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.group.classcontent.a
            public final /* synthetic */ ClassContentListFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Exception {
                ClassContentListFragment classContentListFragment = this.b;
                switch (i2) {
                    case 0:
                        com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.l lVar = (com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.l) obj;
                        String str = ClassContentListFragment.n;
                        if (lVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.k) {
                            long j = ((com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.k) lVar).a;
                            com.quizlet.features.setpage.e eVar = SetPageActivity.h1;
                            Context contextRequireContext = classContentListFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                            classContentListFragment.startActivityForResult(com.quizlet.features.setpage.e.b(eVar, contextRequireContext, j, null, null, null, null, false, null, 252), 201);
                        } else if (lVar instanceof j) {
                            long j2 = ((j) lVar).a;
                            String str2 = FolderActivity.j;
                            Context contextRequireContext2 = classContentListFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                            classContentListFragment.startActivityForResult(AbstractC3309z0.b(contextRequireContext2, j2), 201);
                        } else {
                            if (!(lVar instanceof i)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            long j3 = ((i) lVar).a;
                            Context context = classContentListFragment.getContext();
                            Long lValueOf = Long.valueOf(j3);
                            int i22 = AddClassSetActivity.w;
                            Intent intent = new Intent(context, (Class<?>) AddClassSetActivity.class);
                            intent.putExtra("current_class_id", lValueOf);
                            classContentListFragment.startActivityForResult(intent, 218);
                        }
                        return Unit.a;
                    default:
                        d dVar = (d) obj;
                        String str3 = ClassContentListFragment.n;
                        if (dVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.c) {
                            com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.c cVar = (com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.c) dVar;
                            long j4 = cVar.a;
                            com.quizlet.offline.managers.b bVar = classContentListFragment.j;
                            if (bVar == null) {
                                Intrinsics.m("offlineStateManager");
                                throw null;
                            }
                            Context contextRequireContext3 = classContentListFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                            com.quizlet.features.setpage.e eVar2 = SetPageActivity.h1;
                            Context contextRequireContext4 = classContentListFragment.requireContext();
                            Intrinsics.checkNotNullExpressionValue(contextRequireContext4, "requireContext(...)");
                            ((com.quizlet.offline.managers.i) bVar).d(contextRequireContext3, cVar.b, com.quizlet.features.setpage.e.b(eVar2, contextRequireContext4, j4, null, null, null, null, false, null, 252), new com.quizlet.infra.legacysyncengine.tasks.parse.b(classContentListFragment, 6));
                        } else {
                            if (!(dVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.uicommon.ui.common.dialogs.l.P(R.string.add_class_under_13_title_dialog, R.string.add_class_under_13_msg_dialog, R.string.got_it).O(classContentListFragment.getChildFragmentManager(), "l");
                        }
                        return Unit.a;
                }
            }
        }));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a aVarU = U();
        com.quizlet.local.ormlite.models.term.b bVar = aVarU.d;
        bVar.getClass();
        r stopToken = aVarU.c;
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) bVar.b;
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        androidx.work.impl.model.c cVar2 = (androidx.work.impl.model.c) cVar.b;
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        long j = aVarU.o;
        J jQ = ((androidx.work.impl.model.c) cVar2.c).b(stopToken, new C1510p(cVar2, j, 8)).q(com.quizlet.quizletandroid.ui.group.classcontent.data.b.c);
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        com.quizlet.data.repository.folderwithcreator.e eVar = (com.quizlet.data.repository.folderwithcreator.e) cVar.c;
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        J jQ2 = ((androidx.work.impl.model.c) eVar.d).b(stopToken, new C1510p(eVar, j, 6)).q(com.quizlet.quizletandroid.ui.group.classcontent.data.b.b);
        Intrinsics.checkNotNullExpressionValue(jQ2, "map(...)");
        C4887f c4887f = new C4887f(jQ, 1);
        Intrinsics.checkNotNullExpressionValue(c4887f, "distinctUntilChanged(...)");
        C4887f c4887f2 = new C4887f(jQ2, 1);
        Intrinsics.checkNotNullExpressionValue(c4887f2, "distinctUntilChanged(...)");
        io.reactivex.rxjava3.core.i source1 = io.reactivex.rxjava3.core.i.d(c4887f, c4887f2, new com.quizlet.quizletandroid.ui.group.classcontent.data.b(2));
        Intrinsics.checkNotNullExpressionValue(source1, "Observable.combineLatest…ombineFunction(t1, t2) })");
        g gVarV = aVarU.h.v(aVarU.i, aVarU.p);
        TimeUnit timeUnit = TimeUnit.SECONDS;
        io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(Boolean.FALSE);
        Objects.requireNonNull(timeUnit, "unit is null");
        o oVar = aVarU.j;
        Objects.requireNonNull(oVar, "scheduler is null");
        io.reactivex.rxjava3.core.i source2 = new io.reactivex.rxjava3.internal.operators.single.m(gVarV, 1L, oVar, bVarF).m();
        Intrinsics.checkNotNullExpressionValue(source2, "toObservable(...)");
        Intrinsics.checkNotNullParameter(source1, "source1");
        Intrinsics.checkNotNullParameter(source2, "source2");
        io.reactivex.rxjava3.core.i iVarD = io.reactivex.rxjava3.core.i.d(source1, source2, io.reactivex.rxjava3.kotlin.a.b);
        Intrinsics.checkNotNullExpressionValue(iVarD, "Observable.combineLatest…> { t1, t2 -> t1 to t2 })");
        io.reactivex.rxjava3.disposables.b bVarU = iVarD.u(new com.quizlet.analytics.marketing.e(aVarU, 27), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        Intrinsics.checkNotNullParameter(bVarU, "<this>");
        aVarU.A(bVarU);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        this.l = new com.quizlet.quizletandroid.ui.group.classcontent.adapter.a(U());
        C4611o c4611o = (C4611o) J();
        com.quizlet.quizletandroid.ui.group.classcontent.adapter.a aVar = this.l;
        if (aVar == null) {
            Intrinsics.m("adapter");
            throw null;
        }
        c4611o.c.setAdapter(aVar);
        C4611o c4611o2 = (C4611o) J();
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        com.quizlet.baserecyclerview.decoration.d dVar = com.quizlet.baserecyclerview.decoration.d.a;
        c4611o2.c.i(new com.quizlet.baserecyclerview.decoration.e(contextRequireContext, R.dimen.listitem_vertical_margin));
        C4611o c4611o3 = (C4611o) J();
        requireContext();
        c4611o3.c.setLayoutManager(new LinearLayoutManager(1));
        C4611o c4611o4 = (C4611o) J();
        com.quizlet.infra.legacysyncengine.models.serializers.a aVar2 = new com.quizlet.infra.legacysyncengine.models.serializers.a(20);
        WeakHashMap weakHashMap = V.a;
        L.m(c4611o4.c, aVar2);
    }
}
