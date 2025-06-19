package com.quizlet.features.infra.folder.create.navigation;

import androidx.fragment.app.AbstractC1136h0;
import com.quizlet.features.infra.folder.create.CreateFolderModalFragment;
import com.quizlet.features.infra.navigation.f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements f {
    @Override // com.quizlet.features.infra.navigation.f
    public final void u(AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        String str = CreateFolderModalFragment.w;
        if (fragmentManager.E(str) != null) {
            return;
        }
        new CreateFolderModalFragment().O(fragmentManager, str);
    }
}
