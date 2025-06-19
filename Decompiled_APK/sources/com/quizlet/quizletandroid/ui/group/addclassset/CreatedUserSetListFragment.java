package com.quizlet.quizletandroid.ui.group.addclassset;

import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public class CreatedUserSetListFragment extends Hilt_CreatedUserSetListFragment {
    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final com.quizlet.quizletandroid.ui.base.viewmodel.a X() {
        return (com.quizlet.quizletandroid.ui.base.viewmodel.a) D6.g(requireActivity(), com.quizlet.quizletandroid.ui.group.addclassset.viewmodel.b.class);
    }

    @Override // com.quizlet.quizletandroid.ui.group.addclassset.AddToClassSetListFragment
    public final int b0() {
        return R.string.add_set_created_sets_empty_message;
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.F;
    }
}
