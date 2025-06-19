package com.quizlet.quizletandroid.ui.profile;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.fragment.app.I;
import androidx.recyclerview.widget.AbstractC1361d0;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3707q6;
import com.quizlet.features.infra.legacyadapter.RecyclerViewFragment;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.quizletandroid.R;
import java.lang.ref.WeakReference;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class UserFolderListFragment extends RecyclerViewFragment {
    public static final String z;
    public com.onetrust.otpublishers.headless.UI.viewmodel.c s;
    public com.quizlet.quizletandroid.ui.profile.data.c t;
    public com.quizlet.quizletandroid.ui.common.adapter.ndl.b u;
    public WeakReference v;
    public final kotlin.u w;
    public final kotlin.u x;
    public final com.quizlet.data.interactor.course.a y = new com.quizlet.data.interactor.course.a(this, 29);

    static {
        Intrinsics.checkNotNullExpressionValue("UserFolderListFragment", "getSimpleName(...)");
        z = "UserFolderListFragment";
    }

    public UserFolderListFragment() {
        final int i = 0;
        this.w = kotlin.l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.profile.s
            public final /* synthetic */ UserFolderListFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                UserFolderListFragment userFolderListFragment = this.b;
                switch (i) {
                    case 0:
                        String str = UserFolderListFragment.z;
                        return Long.valueOf(userFolderListFragment.requireArguments().getLong("userId", 0L));
                    default:
                        String str2 = UserFolderListFragment.z;
                        return Boolean.valueOf(userFolderListFragment.requireArguments().getBoolean("includeBookmarks", false));
                }
            }
        });
        final int i2 = 1;
        this.x = kotlin.l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.profile.s
            public final /* synthetic */ UserFolderListFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                UserFolderListFragment userFolderListFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = UserFolderListFragment.z;
                        return Long.valueOf(userFolderListFragment.requireArguments().getLong("userId", 0L));
                    default:
                        String str2 = UserFolderListFragment.z;
                        return Boolean.valueOf(userFolderListFragment.requireArguments().getBoolean("includeBookmarks", false));
                }
            }
        });
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return z;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final AbstractC1361d0 Q() {
        com.quizlet.quizletandroid.ui.common.adapter.ndl.b bVar = new com.quizlet.quizletandroid.ui.common.adapter.ndl.b(this.y);
        this.u = bVar;
        return bVar;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final View R(ViewGroup parent) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View viewInflate = LayoutInflater.from(parent.getContext()).inflate(R.layout.view_empty_viewable_list, parent, false);
        View viewFindViewById = viewInflate.findViewById(R.id.empty_icon);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "findViewById(...)");
        ((IconFontTextView) viewFindViewById).setIcon("folder");
        TextView textView = (TextView) viewInflate.findViewById(R.id.empty_message);
        WeakReference weakReference = this.v;
        if (weakReference == null) {
            Intrinsics.m("mDelegate");
            throw null;
        }
        t tVar = (t) weakReference.get();
        if (tVar != null) {
            ProfileFragment profileFragment = (ProfileFragment) tVar;
            if (profileFragment.X().C(profileFragment.W())) {
                textView.setText(R.string.own_empty_profile_folders);
                return viewInflate;
            }
        }
        textView.setText(R.string.empty_profile_folders);
        return viewInflate;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean T(int i) {
        return true;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean V() {
        return getActivity() instanceof ProfileActivity;
    }

    public final void W() {
        com.quizlet.quizletandroid.ui.profile.data.c cVar = this.t;
        if (cVar == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        final int i = 0;
        cVar.h.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(14, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.r
            public final /* synthetic */ UserFolderListFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                boolean z2 = false;
                UserFolderListFragment userFolderListFragment = this.b;
                switch (i) {
                    case 0:
                        List list = (List) obj;
                        String str = UserFolderListFragment.z;
                        Intrinsics.d(list);
                        userFolderListFragment.getClass();
                        if (list.isEmpty()) {
                            userFolderListFragment.l.b(false);
                        } else {
                            com.quizlet.quizletandroid.ui.common.adapter.ndl.b bVar = userFolderListFragment.u;
                            if (bVar == null) {
                                Intrinsics.m("mFolderAdapter");
                                throw null;
                            }
                            bVar.f(CollectionsKt.n0(list, new com.google.zxing.aztec.encoder.c(20)));
                            userFolderListFragment.l.b(true);
                        }
                        return Unit.a;
                    default:
                        String str2 = UserFolderListFragment.z;
                        com.google.android.material.internal.q qVar = userFolderListFragment.l;
                        if (((Boolean) obj).booleanValue()) {
                            WeakReference weakReference = userFolderListFragment.v;
                            if (weakReference == null) {
                                Intrinsics.m("mDelegate");
                                throw null;
                            }
                            t tVar = (t) weakReference.get();
                            if (tVar != null) {
                                ProfileFragment profileFragment = (ProfileFragment) tVar;
                                if (!profileFragment.X().C(profileFragment.W())) {
                                    z2 = true;
                                }
                            }
                        }
                        qVar.c = z2;
                        qVar.a();
                        return Unit.a;
                }
            }
        }));
        com.quizlet.quizletandroid.ui.profile.data.c cVar2 = this.t;
        if (cVar2 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        final int i2 = 1;
        cVar2.i.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(14, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.profile.r
            public final /* synthetic */ UserFolderListFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                boolean z2 = false;
                UserFolderListFragment userFolderListFragment = this.b;
                switch (i2) {
                    case 0:
                        List list = (List) obj;
                        String str = UserFolderListFragment.z;
                        Intrinsics.d(list);
                        userFolderListFragment.getClass();
                        if (list.isEmpty()) {
                            userFolderListFragment.l.b(false);
                        } else {
                            com.quizlet.quizletandroid.ui.common.adapter.ndl.b bVar = userFolderListFragment.u;
                            if (bVar == null) {
                                Intrinsics.m("mFolderAdapter");
                                throw null;
                            }
                            bVar.f(CollectionsKt.n0(list, new com.google.zxing.aztec.encoder.c(20)));
                            userFolderListFragment.l.b(true);
                        }
                        return Unit.a;
                    default:
                        String str2 = UserFolderListFragment.z;
                        com.google.android.material.internal.q qVar = userFolderListFragment.l;
                        if (((Boolean) obj).booleanValue()) {
                            WeakReference weakReference = userFolderListFragment.v;
                            if (weakReference == null) {
                                Intrinsics.m("mDelegate");
                                throw null;
                            }
                            t tVar = (t) weakReference.get();
                            if (tVar != null) {
                                ProfileFragment profileFragment = (ProfileFragment) tVar;
                                if (!profileFragment.X().C(profileFragment.W())) {
                                    z2 = true;
                                }
                            }
                        }
                        qVar.c = z2;
                        qVar.a();
                        return Unit.a;
                }
            }
        }));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        super.onAttach(context);
        this.v = new WeakReference(AbstractC3707q6.b(this, t.class));
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        I iRequireActivity = requireActivity();
        Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
        com.onetrust.otpublishers.headless.UI.viewmodel.c cVar = this.s;
        if (cVar == null) {
            Intrinsics.m("viewModelFactory");
            throw null;
        }
        com.quizlet.quizletandroid.ui.profile.data.c cVar2 = (com.quizlet.quizletandroid.ui.profile.data.c) D6.f(iRequireActivity, cVar).a(com.quizlet.quizletandroid.ui.profile.data.c.class);
        this.t = cVar2;
        if (cVar2 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        long jLongValue = ((Number) this.w.getValue()).longValue();
        boolean zBooleanValue = ((Boolean) this.x.getValue()).booleanValue();
        cVar2.f = Long.valueOf(jLongValue);
        cVar2.g = zBooleanValue;
        cVar2.B();
        W();
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final void r() {
        this.l.c(true);
        com.quizlet.quizletandroid.ui.profile.data.c cVar = this.t;
        if (cVar == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        cVar.B();
        W();
    }
}
