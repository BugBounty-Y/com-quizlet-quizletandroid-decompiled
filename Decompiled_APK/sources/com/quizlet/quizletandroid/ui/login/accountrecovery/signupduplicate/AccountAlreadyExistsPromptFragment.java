package com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.login.oldlogin.o;
import com.quizlet.login.recovery.data.ScreenState;
import com.quizlet.login.recovery.forgotpassword.ui.ForgotPasswordDialogFragment;
import com.quizlet.login.recovery.forgotpassword.ui.f;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4597a;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.h;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
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
public final class AccountAlreadyExistsPromptFragment extends Hilt_AccountAlreadyExistsPromptFragment<C4597a> {
    public static final String m;
    public com.quizlet.data.repository.user.a j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l;

    static {
        Intrinsics.checkNotNullExpressionValue("AccountAlreadyExistsPromptFragment", "getSimpleName(...)");
        m = "AccountAlreadyExistsPromptFragment";
    }

    public AccountAlreadyExistsPromptFragment() {
        k kVarA = l.a(m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new c(this, 3), 15));
        this.k = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(e.class), new f(kVarA, 19), new h(this, kVarA, 7), new f(kVarA, 20));
        this.l = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(o.class), new c(this, 0), new c(this, 2), new c(this, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return m;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.account_exists_prompt_fragment, viewGroup, false);
        int i = R.id.body;
        if (((QTextView) AbstractC3375o2.c(R.id.body, viewInflate)) != null) {
            i = R.id.enterPassword;
            QFormField qFormField = (QFormField) AbstractC3375o2.c(R.id.enterPassword, viewInflate);
            if (qFormField != null) {
                i = R.id.enterUsername;
                QFormField qFormField2 = (QFormField) AbstractC3375o2.c(R.id.enterUsername, viewInflate);
                if (qFormField2 != null) {
                    i = R.id.existingAccountInformation;
                    ExistingAccountView existingAccountView = (ExistingAccountView) AbstractC3375o2.c(R.id.existingAccountInformation, viewInflate);
                    if (existingAccountView != null) {
                        i = R.id.forgotPasswordLink;
                        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.forgotPasswordLink, viewInflate);
                        if (qTextView != null) {
                            i = R.id.header;
                            if (((QTextView) AbstractC3375o2.c(R.id.header, viewInflate)) != null) {
                                i = R.id.loginButton;
                                AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.loginButton, viewInflate);
                                if (assemblyPrimaryButton != null) {
                                    C4597a c4597a = new C4597a((ConstraintLayout) viewInflate, qFormField, qFormField2, existingAccountView, qTextView, assemblyPrimaryButton);
                                    Intrinsics.checkNotNullExpressionValue(c4597a, "inflate(...)");
                                    return c4597a;
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        e eVar = (e) this.k.getValue();
        ScreenState screenState = (ScreenState) requireArguments().getParcelable("existing_account_info_arg");
        if (screenState == null) {
            throw new IllegalArgumentException("Missing argument: EXISTING_ACCOUNT_INFO_ARG");
        }
        eVar.getClass();
        Intrinsics.checkNotNullParameter(screenState, "screenState");
        eVar.c.l(screenState);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        super.onResume();
        com.quizlet.data.repository.user.a aVar = this.j;
        if (aVar == null) {
            Intrinsics.m("gaLogger");
            throw null;
        }
        Intrinsics.checkNotNullExpressionValue("AccountAlreadyExistsPromptFragment", "getSimpleName(...)");
        aVar.t("AccountAlreadyExistsPromptFragment");
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.k;
        final int i = 0;
        ((e) eVar.getValue()).c.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(11, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.b
            public final /* synthetic */ AccountAlreadyExistsPromptFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                AccountAlreadyExistsPromptFragment accountAlreadyExistsPromptFragment = this.b;
                switch (i) {
                    case 0:
                        ScreenState screenState = (ScreenState) obj;
                        String str = AccountAlreadyExistsPromptFragment.m;
                        if (screenState instanceof ScreenState.KnownAccountExists) {
                            ScreenState.KnownAccountExists knownAccountExists = (ScreenState.KnownAccountExists) screenState;
                            ((C4597a) accountAlreadyExistsPromptFragment.J()).d.setVisibility(0);
                            ((C4597a) accountAlreadyExistsPromptFragment.J()).c.setVisibility(8);
                            C4597a c4597a = (C4597a) accountAlreadyExistsPromptFragment.J();
                            c4597a.c.setText(knownAccountExists.a);
                            C4597a c4597a2 = (C4597a) accountAlreadyExistsPromptFragment.J();
                            String str2 = knownAccountExists.c;
                            if (str2 == null) {
                                str2 = "";
                            }
                            c4597a2.d.p(knownAccountExists.a, knownAccountExists.b, str2, knownAccountExists.d);
                        } else {
                            if (!(screenState instanceof ScreenState.UnknownAccountExists) && !(screenState instanceof ScreenState.MultipleAccountsExist)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            ((C4597a) accountAlreadyExistsPromptFragment.J()).d.setVisibility(8);
                            ((C4597a) accountAlreadyExistsPromptFragment.J()).c.setVisibility(0);
                        }
                        return Unit.a;
                    default:
                        String str3 = AccountAlreadyExistsPromptFragment.m;
                        if (((com.quizlet.quizletandroid.ui.login.accountrecovery.b) obj) instanceof com.quizlet.quizletandroid.ui.login.accountrecovery.b) {
                            new ForgotPasswordDialogFragment().O(accountAlreadyExistsPromptFragment.getChildFragmentManager(), ForgotPasswordDialogFragment.C);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i2 = 1;
        ((e) eVar.getValue()).d.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(11, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.b
            public final /* synthetic */ AccountAlreadyExistsPromptFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                AccountAlreadyExistsPromptFragment accountAlreadyExistsPromptFragment = this.b;
                switch (i2) {
                    case 0:
                        ScreenState screenState = (ScreenState) obj;
                        String str = AccountAlreadyExistsPromptFragment.m;
                        if (screenState instanceof ScreenState.KnownAccountExists) {
                            ScreenState.KnownAccountExists knownAccountExists = (ScreenState.KnownAccountExists) screenState;
                            ((C4597a) accountAlreadyExistsPromptFragment.J()).d.setVisibility(0);
                            ((C4597a) accountAlreadyExistsPromptFragment.J()).c.setVisibility(8);
                            C4597a c4597a = (C4597a) accountAlreadyExistsPromptFragment.J();
                            c4597a.c.setText(knownAccountExists.a);
                            C4597a c4597a2 = (C4597a) accountAlreadyExistsPromptFragment.J();
                            String str2 = knownAccountExists.c;
                            if (str2 == null) {
                                str2 = "";
                            }
                            c4597a2.d.p(knownAccountExists.a, knownAccountExists.b, str2, knownAccountExists.d);
                        } else {
                            if (!(screenState instanceof ScreenState.UnknownAccountExists) && !(screenState instanceof ScreenState.MultipleAccountsExist)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            ((C4597a) accountAlreadyExistsPromptFragment.J()).d.setVisibility(8);
                            ((C4597a) accountAlreadyExistsPromptFragment.J()).c.setVisibility(0);
                        }
                        return Unit.a;
                    default:
                        String str3 = AccountAlreadyExistsPromptFragment.m;
                        if (((com.quizlet.quizletandroid.ui.login.accountrecovery.b) obj) instanceof com.quizlet.quizletandroid.ui.login.accountrecovery.b) {
                            new ForgotPasswordDialogFragment().O(accountAlreadyExistsPromptFragment.getChildFragmentManager(), ForgotPasswordDialogFragment.C);
                        }
                        return Unit.a;
                }
            }
        }));
        C4597a c4597a = (C4597a) J();
        final int i3 = 0;
        c4597a.f.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.a
            public final /* synthetic */ AccountAlreadyExistsPromptFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                AccountAlreadyExistsPromptFragment accountAlreadyExistsPromptFragment = this.b;
                switch (i3) {
                    case 0:
                        ((o) accountAlreadyExistsPromptFragment.l.getValue()).D(String.valueOf(((C4597a) accountAlreadyExistsPromptFragment.J()).c.getText()), String.valueOf(((C4597a) accountAlreadyExistsPromptFragment.J()).b.getText()));
                        break;
                    default:
                        String str = AccountAlreadyExistsPromptFragment.m;
                        e eVar2 = (e) accountAlreadyExistsPromptFragment.k.getValue();
                        eVar2.d.j(com.quizlet.quizletandroid.ui.login.accountrecovery.b.a);
                        break;
                }
            }
        });
        C4597a c4597a2 = (C4597a) J();
        final int i4 = 1;
        c4597a2.e.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.a
            public final /* synthetic */ AccountAlreadyExistsPromptFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                AccountAlreadyExistsPromptFragment accountAlreadyExistsPromptFragment = this.b;
                switch (i4) {
                    case 0:
                        ((o) accountAlreadyExistsPromptFragment.l.getValue()).D(String.valueOf(((C4597a) accountAlreadyExistsPromptFragment.J()).c.getText()), String.valueOf(((C4597a) accountAlreadyExistsPromptFragment.J()).b.getText()));
                        break;
                    default:
                        String str = AccountAlreadyExistsPromptFragment.m;
                        e eVar2 = (e) accountAlreadyExistsPromptFragment.k.getValue();
                        eVar2.d.j(com.quizlet.quizletandroid.ui.login.accountrecovery.b.a);
                        break;
                }
            }
        });
    }
}
