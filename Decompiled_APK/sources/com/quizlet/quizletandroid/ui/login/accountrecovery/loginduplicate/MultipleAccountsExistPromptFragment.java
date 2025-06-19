package com.quizlet.quizletandroid.ui.login.accountrecovery.loginduplicate;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.login.oldlogin.o;
import com.quizlet.login.recovery.forgotpassword.ui.f;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.P;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.h;
import com.quizlet.quizletandroid.ui.common.ads.G;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;

@Metadata
/* loaded from: classes3.dex */
public final class MultipleAccountsExistPromptFragment extends Hilt_MultipleAccountsExistPromptFragment<P> {
    public static final String l;
    public final e j;
    public final e k;

    static {
        Intrinsics.checkNotNullExpressionValue("MultipleAccountsExistPromptFragment", "getSimpleName(...)");
        l = "MultipleAccountsExistPromptFragment";
    }

    public MultipleAccountsExistPromptFragment() {
        k kVarA = l.a(m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new b(this, 3), 14));
        this.j = new e(K.a(d.class), new f(kVarA, 17), new h(this, kVarA, 6), new f(kVarA, 18));
        this.k = new e(K.a(o.class), new b(this, 0), new b(this, 2), new b(this, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return l;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.multiple_accounts_exist_prompt_fragment, viewGroup, false);
        int i = R.id.body;
        if (((QTextView) AbstractC3375o2.c(R.id.body, viewInflate)) != null) {
            i = R.id.enterUsername;
            QFormField qFormField = (QFormField) AbstractC3375o2.c(R.id.enterUsername, viewInflate);
            if (qFormField != null) {
                i = R.id.forgotUsernameLink;
                AssemblySecondaryButton assemblySecondaryButton = (AssemblySecondaryButton) AbstractC3375o2.c(R.id.forgotUsernameLink, viewInflate);
                if (assemblySecondaryButton != null) {
                    i = R.id.header;
                    if (((QTextView) AbstractC3375o2.c(R.id.header, viewInflate)) != null) {
                        i = R.id.loginButton;
                        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.loginButton, viewInflate);
                        if (assemblyPrimaryButton != null) {
                            P p = new P((ConstraintLayout) viewInflate, qFormField, assemblySecondaryButton, assemblyPrimaryButton);
                            Intrinsics.checkNotNullExpressionValue(p, "inflate(...)");
                            return p;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((d) this.j.getValue()).c.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.fragments.c(new G(this, 11), (short) 0));
        P p = (P) J();
        final int i = 0;
        p.c.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.login.accountrecovery.loginduplicate.a
            public final /* synthetic */ MultipleAccountsExistPromptFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                MultipleAccountsExistPromptFragment multipleAccountsExistPromptFragment = this.b;
                switch (i) {
                    case 0:
                        String str = MultipleAccountsExistPromptFragment.l;
                        ((d) multipleAccountsExistPromptFragment.j.getValue()).c.j(Unit.a);
                        break;
                    default:
                        o oVar = (o) multipleAccountsExistPromptFragment.k.getValue();
                        String username = String.valueOf(((P) multipleAccountsExistPromptFragment.J()).b.getText());
                        oVar.getClass();
                        Intrinsics.checkNotNullParameter(username, "username");
                        String str2 = oVar.x;
                        if (str2 != null) {
                            oVar.D(username, str2);
                            break;
                        }
                        break;
                }
            }
        });
        P p2 = (P) J();
        final int i2 = 1;
        p2.d.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.login.accountrecovery.loginduplicate.a
            public final /* synthetic */ MultipleAccountsExistPromptFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                MultipleAccountsExistPromptFragment multipleAccountsExistPromptFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = MultipleAccountsExistPromptFragment.l;
                        ((d) multipleAccountsExistPromptFragment.j.getValue()).c.j(Unit.a);
                        break;
                    default:
                        o oVar = (o) multipleAccountsExistPromptFragment.k.getValue();
                        String username = String.valueOf(((P) multipleAccountsExistPromptFragment.J()).b.getText());
                        oVar.getClass();
                        Intrinsics.checkNotNullParameter(username, "username");
                        String str2 = oVar.x;
                        if (str2 != null) {
                            oVar.D(username, str2);
                            break;
                        }
                        break;
                }
            }
        });
    }
}
