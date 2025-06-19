package com.quizlet.quizletandroid.ui.setpage.addset;

import android.os.Bundle;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3760x4;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.h;
import com.quizlet.quizletandroid.ui.setcreation.managers.n;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.operators.observable.E;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class LoggedInUserClassSelectionListFragment extends Hilt_LoggedInUserClassSelectionListFragment {
    public static final String F;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e A = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(c.class), new d(this, 0), new d(this, 2), new d(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e B;
    public com.quizlet.infra.legacysyncengine.managers.d C;
    public o D;
    public final n E;

    static {
        Intrinsics.checkNotNullExpressionValue("LoggedInUserClassSelectionListFragment", "getSimpleName(...)");
        F = "LoggedInUserClassSelectionListFragment";
    }

    public LoggedInUserClassSelectionListFragment() {
        k kVarA = l.a(m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new d(this, 3), 21));
        this.B = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(f.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 27), new h(this, kVarA, 11), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 28));
        this.E = new n(this, 1);
    }

    @Override // com.quizlet.quizletandroid.ui.profile.UserClassListFragment, com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return F;
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final com.quizlet.quizletandroid.ui.base.viewmodel.a X() {
        return (f) this.B.getValue();
    }

    @Override // com.quizlet.quizletandroid.ui.profile.UserClassListFragment, com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    /* renamed from: b0 */
    public final com.quizlet.features.infra.legacyadapter.e Q() {
        if (this.C == null) {
            Intrinsics.m("loggedInUserManager");
            throw null;
        }
        com.quizlet.features.infra.legacyadapter.e mGroupAdapter = new com.quizlet.features.infra.legacyadapter.e(((c) this.A.getValue()).e, this.E, null);
        this.t = mGroupAdapter;
        Intrinsics.checkNotNullExpressionValue(mGroupAdapter, "mGroupAdapter");
        return mGroupAdapter;
    }

    @Override // com.quizlet.quizletandroid.ui.profile.UserClassListFragment
    public final List c0(ArrayList arrayList) {
        return AbstractC3760x4.b(arrayList, true);
    }

    @Override // com.quizlet.quizletandroid.ui.profile.UserClassListFragment
    public final int d0() {
        return R.string.own_empty_profile_classes;
    }

    @Override // com.quizlet.quizletandroid.ui.profile.UserClassListFragment
    public final boolean e0() {
        return true;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        i iVar;
        super.onStart();
        c cVar = (c) this.A.getValue();
        if (cVar.h) {
            iVar = E.a;
            Intrinsics.checkNotNullExpressionValue(iVar, "empty(...)");
        } else {
            u uVar = cVar.g;
            com.quizlet.infra.legacysyncengine.orm.query.a aVar = (com.quizlet.infra.legacysyncengine.orm.query.a) uVar.getValue();
            com.quizlet.infra.legacysyncengine.net.c cVar2 = cVar.c;
            cVar2.e(aVar, cVar.j);
            cVar2.c((com.quizlet.infra.legacysyncengine.orm.query.a) uVar.getValue(), com.quizlet.infra.legacysyncengine.net.c.e);
            iVar = cVar.i;
        }
        o oVar = this.D;
        if (oVar == null) {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
        io.reactivex.rxjava3.disposables.b bVarU = iVar.s(oVar).u(new com.quizlet.analytics.marketing.e(this, 29), new com.quizlet.billing.manager.d(timber.log.c.a, 13), io.reactivex.rxjava3.internal.functions.d.c);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        I(bVarU);
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment, com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((com.quizlet.features.infra.legacyadapter.databinding.a) J()).i.setEnabled(false);
    }
}
