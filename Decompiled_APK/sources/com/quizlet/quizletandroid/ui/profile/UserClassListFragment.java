package com.quizlet.quizletandroid.ui.profile;

import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3760x4;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class UserClassListFragment extends ViewModelDataSourceRecyclerViewFragment<DBGroupMembership> {
    public com.quizlet.features.infra.legacyadapter.e t;
    public final com.quizlet.login.authentication.login.a u = new com.quizlet.login.authentication.login.a(this, 9);

    @Override // com.quizlet.baseui.base.BaseFragment
    public String N() {
        return "UserClassListFragment";
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final View R(ViewGroup viewGroup) {
        View viewC = Z.c(viewGroup, R.layout.view_empty_viewable_list, viewGroup, false);
        ((IconFontTextView) viewC.findViewById(R.id.empty_icon)).setIcon(AssociationNames.CLASS);
        TextView textView = (TextView) viewC.findViewById(R.id.empty_message);
        if (e0()) {
            textView.setText(d0());
            return viewC;
        }
        textView.setText(R.string.empty_profile_classes);
        return viewC;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean T(int i) {
        return this.t.d(i) != null;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean V() {
        return getActivity() instanceof ProfileActivity;
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final void W(List list) {
        this.t.g(c0(new ArrayList(list)));
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final boolean a0() {
        return !e0();
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    /* renamed from: b0, reason: merged with bridge method [inline-methods] */
    public com.quizlet.features.infra.legacyadapter.e Q() {
        com.quizlet.features.infra.legacyadapter.e eVar = new com.quizlet.features.infra.legacyadapter.e(null, this.u, null);
        this.t = eVar;
        return eVar;
    }

    public List c0(ArrayList groupMemberships) {
        Intrinsics.checkNotNullParameter(groupMemberships, "groupMemberships");
        return AbstractC3760x4.b(groupMemberships, false);
    }

    public int d0() {
        return R.string.own_empty_classes;
    }

    public abstract boolean e0();

    public void f0(long j) {
    }
}
