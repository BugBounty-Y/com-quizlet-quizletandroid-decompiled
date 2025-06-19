package com.quizlet.quizletandroid.ui.joincontenttofolder;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.fragment.app.I;
import androidx.recyclerview.widget.AbstractC1361d0;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.quizlet.features.infra.legacyadapter.RecyclerViewFragment;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.ads.G;
import com.quizlet.quizletandroid.ui.globalnav.composable.s;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class SelectableFolderListFragment extends RecyclerViewFragment {
    public static final String v;
    public com.onetrust.otpublishers.headless.UI.viewmodel.c s;
    public k t;
    public m u;

    static {
        Intrinsics.checkNotNullExpressionValue("SelectableFolderListFragment", "getSimpleName(...)");
        v = "SelectableFolderListFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return v;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final AbstractC1361d0 Q() {
        m mVar = new m(new s(1, this, SelectableFolderListFragment.class, "onFolderClicked", "onFolderClicked(J)V", 0, 2), new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 6));
        this.u = mVar;
        return mVar;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final View R(ViewGroup parent) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View viewInflate = LayoutInflater.from(parent.getContext()).inflate(R.layout.view_empty_viewable_list, parent, false);
        ((IconFontTextView) viewInflate.findViewById(R.id.empty_icon)).setIcon("folder");
        ((TextView) viewInflate.findViewById(R.id.empty_message)).setText(R.string.empty_profile_folders);
        return viewInflate;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean T(int i) {
        return true;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        I iRequireActivity = requireActivity();
        Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
        com.onetrust.otpublishers.headless.UI.viewmodel.c cVar = this.s;
        if (cVar == null) {
            Intrinsics.m("viewModelFactory");
            throw null;
        }
        k kVar = (k) D6.f(iRequireActivity, cVar).a(k.class);
        this.t = kVar;
        if (kVar != null) {
            kVar.r.f(this, new com.quizlet.ads.ui.fragments.c(new G(this, 9), (char) 0));
        } else {
            Intrinsics.m("viewModel");
            throw null;
        }
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        this.j.setRefreshing(false);
        this.j.setEnabled(false);
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final void r() {
    }
}
