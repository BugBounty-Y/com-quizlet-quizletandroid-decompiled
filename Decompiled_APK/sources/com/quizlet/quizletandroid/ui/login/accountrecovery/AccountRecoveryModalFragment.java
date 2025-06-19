package com.quizlet.quizletandroid.ui.login.accountrecovery;

import android.os.Bundle;
import android.widget.FrameLayout;
import androidx.compose.ui.node.B;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.login.recovery.data.ScreenState;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.login.accountrecovery.loginduplicate.MultipleAccountsExistPromptFragment;
import com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.AccountAlreadyExistsPromptFragment;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class AccountRecoveryModalFragment extends Hilt_AccountRecoveryModalFragment {
    public static final String I;

    static {
        Intrinsics.checkNotNullExpressionValue("AccountRecoveryModalFragment", "getSimpleName(...)");
        I = "AccountRecoveryModalFragment";
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, AbstractC1136h0 fragmentManager) {
        BaseFragment multipleAccountsExistPromptFragment;
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        ScreenState existingAccountInfo = (ScreenState) requireArguments().getParcelable("existing_account_info_arg");
        if (existingAccountInfo == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        if ((existingAccountInfo instanceof ScreenState.KnownAccountExists) || existingAccountInfo.equals(ScreenState.UnknownAccountExists.a)) {
            String str = AccountAlreadyExistsPromptFragment.m;
            Intrinsics.checkNotNullParameter(existingAccountInfo, "existingAccountInfo");
            AccountAlreadyExistsPromptFragment accountAlreadyExistsPromptFragment = new AccountAlreadyExistsPromptFragment();
            Bundle bundle = new Bundle();
            bundle.putParcelable("existing_account_info_arg", existingAccountInfo);
            accountAlreadyExistsPromptFragment.setArguments(bundle);
            multipleAccountsExistPromptFragment = accountAlreadyExistsPromptFragment;
        } else {
            if (!existingAccountInfo.equals(ScreenState.MultipleAccountsExist.a)) {
                throw new NoWhenBranchMatchedException();
            }
            multipleAccountsExistPromptFragment = new MultipleAccountsExistPromptFragment();
        }
        C1121a c1121aB = B.b(fragmentManager, fragmentManager);
        c1121aB.l(R.id.contentFragment, multipleAccountsExistPromptFragment, multipleAccountsExistPromptFragment.N());
        c1121aB.g();
    }
}
