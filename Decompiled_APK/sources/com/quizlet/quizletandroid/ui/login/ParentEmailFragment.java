package com.quizlet.quizletandroid.ui.login;

import android.content.Context;
import android.content.res.Resources;
import android.os.Bundle;
import android.text.method.LinkMovementMethod;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class ParentEmailFragment extends Hilt_ParentEmailFragment<com.quizlet.login.databinding.a> {
    public static final String n;
    public io.reactivex.rxjava3.core.o j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l;
    public final kotlin.u m;

    static {
        Intrinsics.checkNotNullExpressionValue("ParentEmailFragment", "getSimpleName(...)");
        n = "ParentEmailFragment";
    }

    public ParentEmailFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new v(this, 3), 11));
        this.k = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.login.viewmodels.f.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 13), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 4), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 14));
        this.l = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.login.oldlogin.o.class), new v(this, 0), new v(this, 2), new v(this, 1));
        this.m = kotlin.l.b(new com.quizlet.login.magiclink.ui.e(this, 18));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return n;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_parent_email, viewGroup, false);
        int i = R.id.parentEmailEditText;
        AssemblyInputEditText assemblyInputEditText = (AssemblyInputEditText) AbstractC3375o2.c(R.id.parentEmailEditText, viewInflate);
        if (assemblyInputEditText != null) {
            i = R.id.parentEmailInputLayout;
            AssemblyInputLayout assemblyInputLayout = (AssemblyInputLayout) AbstractC3375o2.c(R.id.parentEmailInputLayout, viewInflate);
            if (assemblyInputLayout != null) {
                i = R.id.parentEmailSubTitle;
                TextView textView = (TextView) AbstractC3375o2.c(R.id.parentEmailSubTitle, viewInflate);
                if (textView != null) {
                    i = R.id.parentEmailTitle;
                    if (((TextView) AbstractC3375o2.c(R.id.parentEmailTitle, viewInflate)) != null) {
                        i = R.id.parentPasswordEditText;
                        AssemblyInputEditText assemblyInputEditText2 = (AssemblyInputEditText) AbstractC3375o2.c(R.id.parentPasswordEditText, viewInflate);
                        if (assemblyInputEditText2 != null) {
                            i = R.id.parentPasswordInputLayout;
                            AssemblyInputLayout assemblyInputLayout2 = (AssemblyInputLayout) AbstractC3375o2.c(R.id.parentPasswordInputLayout, viewInflate);
                            if (assemblyInputLayout2 != null) {
                                i = R.id.signupButton;
                                AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.signupButton, viewInflate);
                                if (assemblyPrimaryButton != null) {
                                    i = R.id.signupTos;
                                    TextView textView2 = (TextView) AbstractC3375o2.c(R.id.signupTos, viewInflate);
                                    if (textView2 != null) {
                                        com.quizlet.login.databinding.a aVar = new com.quizlet.login.databinding.a((ConstraintLayout) viewInflate, assemblyInputEditText, assemblyInputLayout, textView, assemblyInputEditText2, assemblyInputLayout2, assemblyPrimaryButton, textView2);
                                        Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
                                        return aVar;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final com.quizlet.quizletandroid.ui.login.viewmodels.f T() {
        return (com.quizlet.quizletandroid.ui.login.viewmodels.f) this.k.getValue();
    }

    public final void U(AssemblyInputEditText assemblyInputEditText, Function0 function0, final Function1 function1) {
        com.jakewharton.rxbinding4.widget.c cVar = new com.jakewharton.rxbinding4.widget.c(assemblyInputEditText);
        com.quizlet.analytics.marketing.e eVar = new com.quizlet.analytics.marketing.e(function0);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        io.reactivex.rxjava3.internal.operators.observable.B b = new io.reactivex.rxjava3.internal.operators.observable.B(cVar, eVar, gVar, bVar, bVar);
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        io.reactivex.rxjava3.core.o oVar = this.j;
        if (oVar == null) {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
        J jQ = b.h(500L, timeUnit, oVar).q(g.c);
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        final int i = 0;
        final int i2 = 1;
        H(B7.d(jQ, new Function1(i, function1) { // from class: com.quizlet.quizletandroid.ui.login.q
            public final /* synthetic */ int a;
            public final /* synthetic */ C4956o b;

            /* JADX WARN: Multi-variable type inference failed */
            {
                this.b = (C4956o) function1;
            }

            /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.o] */
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                ?? r0 = this.b;
                switch (this.a) {
                    case 0:
                        String str = ParentEmailFragment.n;
                        Intrinsics.checkNotNullParameter((Throwable) obj, "it");
                        r0.invoke("");
                        break;
                    default:
                        String it2 = (String) obj;
                        String str2 = ParentEmailFragment.n;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        r0.invoke(it2);
                        break;
                }
                return Unit.a;
            }
        }, null, new Function1(i2, function1) { // from class: com.quizlet.quizletandroid.ui.login.q
            public final /* synthetic */ int a;
            public final /* synthetic */ C4956o b;

            /* JADX WARN: Multi-variable type inference failed */
            {
                this.b = (C4956o) function1;
            }

            /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.o] */
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                ?? r0 = this.b;
                switch (this.a) {
                    case 0:
                        String str = ParentEmailFragment.n;
                        Intrinsics.checkNotNullParameter((Throwable) obj, "it");
                        r0.invoke("");
                        break;
                    default:
                        String it2 = (String) obj;
                        String str2 = ParentEmailFragment.n;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        r0.invoke(it2);
                        break;
                }
                return Unit.a;
            }
        }, 2));
    }

    public final void V(AssemblyInputLayout assemblyInputLayout, com.quizlet.quizletandroid.ui.login.viewmodels.d dVar) {
        if (Intrinsics.b(dVar, com.quizlet.quizletandroid.ui.login.viewmodels.a.a) || Intrinsics.b(dVar, com.quizlet.quizletandroid.ui.login.viewmodels.c.a)) {
            assemblyInputLayout.setError(null);
        } else {
            if (!(dVar instanceof com.quizlet.quizletandroid.ui.login.viewmodels.b)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.qutils.string.f fVar = ((com.quizlet.quizletandroid.ui.login.viewmodels.b) dVar).a;
            Context contextRequireContext = requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
            assemblyInputLayout.setError(AbstractC3053s1.e(fVar, contextRequireContext));
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((com.quizlet.login.databinding.a) J()).g.setEnabled(false);
        ((com.quizlet.login.databinding.a) J()).c.setError(null);
        ((com.quizlet.login.databinding.a) J()).f.setError(null);
        if (((com.quizlet.login.oldlogin.b) this.m.getValue()) == com.quizlet.login.oldlogin.b.b) {
            com.quizlet.login.databinding.a aVar = (com.quizlet.login.databinding.a) J();
            aVar.d.setText(getString(R.string.parent_email_and_password_subtitle));
            ((com.quizlet.login.databinding.a) J()).b.setImeOptions(5);
            AssemblyInputLayout parentPasswordInputLayout = ((com.quizlet.login.databinding.a) J()).f;
            Intrinsics.checkNotNullExpressionValue(parentPasswordInputLayout, "parentPasswordInputLayout");
            parentPasswordInputLayout.setVisibility(0);
        } else {
            com.quizlet.login.databinding.a aVar2 = (com.quizlet.login.databinding.a) J();
            aVar2.d.setText(getString(R.string.parent_email_subtitle));
            ((com.quizlet.login.databinding.a) J()).b.setImeOptions(6);
            AssemblyInputLayout parentPasswordInputLayout2 = ((com.quizlet.login.databinding.a) J()).f;
            Intrinsics.checkNotNullExpressionValue(parentPasswordInputLayout2, "parentPasswordInputLayout");
            parentPasswordInputLayout2.setVisibility(8);
        }
        androidx.lifecycle.J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new u(this, null), 3);
        com.quizlet.login.databinding.a aVar3 = (com.quizlet.login.databinding.a) J();
        aVar3.g.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 9));
        com.quizlet.login.databinding.a aVar4 = (com.quizlet.login.databinding.a) J();
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        aVar4.h.setText(androidx.camera.core.impl.utils.e.c(contextRequireContext, R.attr.SysColorTextSecondary, Integer.valueOf(R.style.SubHeader_S5)));
        ((com.quizlet.login.databinding.a) J()).h.setMovementMethod(LinkMovementMethod.getInstance());
        AssemblyInputEditText parentEmailEditText = ((com.quizlet.login.databinding.a) J()).b;
        Intrinsics.checkNotNullExpressionValue(parentEmailEditText, "parentEmailEditText");
        U(parentEmailEditText, new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, T(), com.quizlet.quizletandroid.ui.login.viewmodels.f.class, "onEnteringEmail", "onEnteringEmail()V", 0, 10), new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, T(), com.quizlet.quizletandroid.ui.login.viewmodels.f.class, "onEmailEntered", "onEmailEntered(Ljava/lang/String;)V", 0, 17));
        AssemblyInputEditText parentPasswordEditText = ((com.quizlet.login.databinding.a) J()).e;
        Intrinsics.checkNotNullExpressionValue(parentPasswordEditText, "parentPasswordEditText");
        U(parentPasswordEditText, new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, T(), com.quizlet.quizletandroid.ui.login.viewmodels.f.class, "onEnteringPassword", "onEnteringPassword()V", 0, 11), new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, T(), com.quizlet.quizletandroid.ui.login.viewmodels.f.class, "onPasswordEntered", "onPasswordEntered(Ljava/lang/String;)V", 0, 18));
    }
}
