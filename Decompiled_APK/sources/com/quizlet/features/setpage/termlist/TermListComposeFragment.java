package com.quizlet.features.setpage.termlist;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.lifecycle.p0;
import androidx.navigation.serialization.i;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.features.flashcards.C4239m;
import com.quizlet.features.setpage.r;
import com.quizlet.features.setpage.termlist.data.g;
import com.quizlet.features.setpage.termlist.data.m;
import com.quizlet.features.setpage.termlist.viewmodel.j;
import java.lang.ref.WeakReference;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class TermListComposeFragment extends Hilt_TermListComposeFragment<androidx.viewbinding.a> implements com.quizlet.features.setpage.termlist.contracts.a {
    public static final String m;
    public com.google.mlkit.common.sdkinternal.b j;
    public WeakReference k;
    public final e l = new e(K.a(j.class), new c(this, 0), new c(this, 2), new c(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("TermListComposeFragment", "getSimpleName(...)");
        m = "TermListComposeFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return m;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 17);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-2145082361);
        if ((((c0814p2.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(U().h, c0814p2);
            j jVarU = U();
            c0814p2.X(340510326);
            boolean zF = c0814p2.f(jVarU);
            Object objI = c0814p2.I();
            V v = C0804k.a;
            if (zF || objI == v) {
                objI = new com.quizlet.featuregate.growthbook.a(this, 14);
                c0814p2.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            c0814p2.p(false);
            j jVarU2 = U();
            c0814p2.X(340513631);
            boolean zF2 = c0814p2.f(jVarU2);
            Object objI2 = c0814p2.I();
            if (zF2 || objI2 == v) {
                objI2 = new a(this);
                c0814p2.i0(objI2);
            }
            Function2 function2 = (Function2) objI2;
            c0814p2.p(false);
            j jVarU3 = U();
            c0814p2.X(340520047);
            boolean zF3 = c0814p2.f(jVarU3);
            Object objI3 = c0814p2.I();
            if (zF3 || objI3 == v) {
                final int i2 = 0;
                objI3 = new Function1(this) { // from class: com.quizlet.features.setpage.termlist.b
                    public final /* synthetic */ TermListComposeFragment b;

                    {
                        this.b = this;
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        TermListComposeFragment termListComposeFragment = this.b;
                        switch (i2) {
                            case 0:
                                m sortOption = (m) obj;
                                String str = TermListComposeFragment.m;
                                Intrinsics.checkNotNullParameter(sortOption, "sortOption");
                                termListComposeFragment.U().B(new g(sortOption));
                                break;
                            default:
                                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                                String str2 = TermListComposeFragment.m;
                                termListComposeFragment.U().B(new com.quizlet.features.setpage.termlist.data.d(zBooleanValue));
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objI3);
            }
            Function1 function1 = (Function1) objI3;
            c0814p2.p(false);
            j jVarU4 = U();
            c0814p2.X(340527398);
            boolean zF4 = c0814p2.f(jVarU4);
            Object objI4 = c0814p2.I();
            if (zF4 || objI4 == v) {
                objI4 = new com.quizlet.features.infra.folder.create.b(this, 1);
                c0814p2.i0(objI4);
            }
            kotlin.jvm.functions.d dVar = (kotlin.jvm.functions.d) objI4;
            c0814p2.p(false);
            j jVarU5 = U();
            c0814p2.X(340538447);
            boolean zF5 = c0814p2.f(jVarU5);
            Object objI5 = c0814p2.I();
            if (zF5 || objI5 == v) {
                objI5 = new i(this, 3);
                c0814p2.i0(objI5);
            }
            kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) objI5;
            c0814p2.p(false);
            j jVarU6 = U();
            c0814p2.X(340547758);
            boolean zF6 = c0814p2.f(jVarU6);
            Object objI6 = c0814p2.I();
            if (zF6 || objI6 == v) {
                final int i3 = 1;
                objI6 = new Function1(this) { // from class: com.quizlet.features.setpage.termlist.b
                    public final /* synthetic */ TermListComposeFragment b;

                    {
                        this.b = this;
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        TermListComposeFragment termListComposeFragment = this.b;
                        switch (i3) {
                            case 0:
                                m sortOption = (m) obj;
                                String str = TermListComposeFragment.m;
                                Intrinsics.checkNotNullParameter(sortOption, "sortOption");
                                termListComposeFragment.U().B(new g(sortOption));
                                break;
                            default:
                                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                                String str2 = TermListComposeFragment.m;
                                termListComposeFragment.U().B(new com.quizlet.features.setpage.termlist.data.d(zBooleanValue));
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objI6);
            }
            c0814p2.p(false);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(-3115673, new C4239m(this, function1, function0, function2, dVar, cVar, (Function1) objI6, interfaceC0773a0M), c0814p2);
            c0814p = c0814p2;
            AbstractC3178j5.b(null, false, null, dVarE, c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new a(this, i);
        }
    }

    public final j U() {
        return (j) this.l.getValue();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.quizlet.features.setpage.termlist.Hilt_TermListComposeFragment, com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        super.onAttach(context);
        this.k = context instanceof com.quizlet.features.setpage.termlist.contracts.b ? new WeakReference((com.quizlet.features.setpage.termlist.contracts.b) context) : new WeakReference(null);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDetach() {
        super.onDetach();
        WeakReference weakReference = this.k;
        if (weakReference != null) {
            weakReference.clear();
        } else {
            Intrinsics.m("loadingSpinnerDelegate");
            throw null;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        super.onResume();
        j jVarU = U();
        jVarU.getClass();
        E.A(p0.j(jVarU), null, null, new com.quizlet.features.setpage.termlist.viewmodel.c(jVarU, null), 3);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        WeakReference weakReference = this.k;
        if (weakReference == null) {
            Intrinsics.m("loadingSpinnerDelegate");
            throw null;
        }
        if (weakReference.get() != null) {
            WeakReference weakReference2 = this.k;
            if (weakReference2 == null) {
                Intrinsics.m("loadingSpinnerDelegate");
                throw null;
            }
            com.quizlet.features.setpage.termlist.contracts.b bVar = (com.quizlet.features.setpage.termlist.contracts.b) weakReference2.get();
            if (bVar != null) {
                ((r) bVar).U(false);
            }
        }
    }
}
