package com.quizlet.quizletandroid.ui.profile;

import android.content.Context;
import com.quizlet.quizletandroid.ui.group.GroupActivity;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class ProfileUserClassListFragment extends Hilt_ProfileUserClassListFragment {
    public final com.quizlet.data.repository.folderwithcreatorinclass.e A;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e B;
    public final kotlin.u C;

    public ProfileUserClassListFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new m(this, 3), 16));
        this.A = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(o.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 21), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 8), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 22));
        this.B = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.profile.data.h.class), new m(this, 0), new m(this, 2), new m(this, 1));
        this.C = kotlin.l.b(new com.quizlet.login.magiclink.ui.e(this, 20));
    }

    @Override // com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment
    public final com.quizlet.quizletandroid.ui.base.viewmodel.a X() {
        return (o) this.A.getValue();
    }

    @Override // com.quizlet.quizletandroid.ui.profile.UserClassListFragment
    public final boolean e0() {
        return ((com.quizlet.quizletandroid.ui.profile.data.h) this.B.getValue()).C(((Number) this.C.getValue()).longValue());
    }

    @Override // com.quizlet.quizletandroid.ui.profile.UserClassListFragment
    public final void f0(long j) {
        String str = GroupActivity.u;
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        startActivity(com.quizlet.quizletandroid.ui.group.f.a(contextRequireContext, Long.valueOf(j), null, false, null));
    }
}
