package com.quizlet.search;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.fragment.app.I;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3313z4;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.t;
import com.quizlet.search.viewmodels.p;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.m;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class NewSearchFragment extends Hilt_NewSearchFragment<androidx.viewbinding.a> {
    public static final String o;
    public com.quizlet.quizletandroid.ui.navigationmanagers.g j;
    public androidx.activity.result.b k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l;
    public final u m;
    public final u n;

    static {
        Intrinsics.checkNotNullExpressionValue("NewSearchFragment", "getSimpleName(...)");
        o = "NewSearchFragment";
    }

    public NewSearchFragment() {
        kotlin.k kVarA = kotlin.l.a(m.c, new t(new t(this, 5), 6));
        this.l = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(p.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 13), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 28), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 14));
        final int i = 0;
        this.m = kotlin.l.b(new Function0(this) { // from class: com.quizlet.search.a
            public final /* synthetic */ NewSearchFragment b;

            {
                this.b = this;
            }

            /* JADX WARN: Removed duplicated region for block: B:9:0x0019  */
            @Override // kotlin.jvm.functions.Function0
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public final java.lang.Object invoke() {
                /*
                    r2 = this;
                    com.quizlet.search.NewSearchFragment r0 = r2.b
                    int r1 = r2
                    switch(r1) {
                        case 0: goto L1f;
                        default: goto L7;
                    }
                L7:
                    java.lang.String r1 = com.quizlet.search.NewSearchFragment.o
                    android.os.Bundle r0 = r0.getArguments()
                    if (r0 == 0) goto L19
                    java.lang.String r1 = "hasBottomBar"
                    boolean r0 = r0.getBoolean(r1)
                    r1 = 1
                    if (r0 != r1) goto L19
                    goto L1a
                L19:
                    r1 = 0
                L1a:
                    java.lang.Boolean r0 = java.lang.Boolean.valueOf(r1)
                    return r0
                L1f:
                    java.lang.String r1 = com.quizlet.search.NewSearchFragment.o
                    android.os.Bundle r0 = r0.requireArguments()
                    java.lang.String r1 = "searchQuery"
                    java.lang.String r0 = r0.getString(r1)
                    return r0
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.search.a.invoke():java.lang.Object");
            }
        });
        final int i2 = 1;
        this.n = kotlin.l.b(new Function0(this) { // from class: com.quizlet.search.a
            public final /* synthetic */ NewSearchFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                /*
                    this = this;
                    com.quizlet.search.NewSearchFragment r0 = r2.b
                    int r1 = r2
                    switch(r1) {
                        case 0: goto L1f;
                        default: goto L7;
                    }
                L7:
                    java.lang.String r1 = com.quizlet.search.NewSearchFragment.o
                    android.os.Bundle r0 = r0.getArguments()
                    if (r0 == 0) goto L19
                    java.lang.String r1 = "hasBottomBar"
                    boolean r0 = r0.getBoolean(r1)
                    r1 = 1
                    if (r0 != r1) goto L19
                    goto L1a
                L19:
                    r1 = 0
                L1a:
                    java.lang.Boolean r0 = java.lang.Boolean.valueOf(r1)
                    return r0
                L1f:
                    java.lang.String r1 = com.quizlet.search.NewSearchFragment.o
                    android.os.Bundle r0 = r0.requireArguments()
                    java.lang.String r1 = "searchQuery"
                    java.lang.String r0 = r0.getString(r1)
                    return r0
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.search.a.invoke():java.lang.Object");
            }
        });
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return o;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new b(this, 0);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1123642981);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            I iRequireActivity = requireActivity();
            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
            AbstractC3178j5.b(AbstractC3313z4.e(iRequireActivity, c0814p), false, com.quizlet.themes.i.a, androidx.compose.runtime.internal.e.e(1441229883, new c(this, 0), c0814p), c0814p, 3072, 2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(this, i, 16);
        }
    }

    public final com.quizlet.search.navigation.m U() {
        com.quizlet.quizletandroid.ui.navigationmanagers.g gVar = this.j;
        if (gVar != null) {
            return gVar;
        }
        Intrinsics.m("navigationManager");
        throw null;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.k = registerForActivityResult(new androidx.activity.result.contract.b(4), new androidx.activity.compose.b(this, 6));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new f(this, null), 3);
        String query = (String) this.m.getValue();
        if (query != null) {
            p pVar = (p) this.l.getValue();
            pVar.getClass();
            Intrinsics.checkNotNullParameter(query, "query");
            pVar.n = query;
            pVar.B(query, true);
        }
    }
}
