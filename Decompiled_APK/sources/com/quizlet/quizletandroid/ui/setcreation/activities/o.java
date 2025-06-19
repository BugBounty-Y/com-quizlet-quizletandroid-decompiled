package com.quizlet.quizletandroid.ui.setcreation.activities;

import androidx.compose.ui.platform.C0960p;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.F0;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o extends F0 {
    public final com.onetrust.otpublishers.headless.databinding.b a;
    public final C0960p b;
    public final ArrayList c;
    public final boolean d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(com.onetrust.otpublishers.headless.databinding.b binding, C0960p permissionItemClickCallback, ArrayList permissions, boolean z) {
        super((ConstraintLayout) binding.b);
        Intrinsics.checkNotNullParameter(binding, "binding");
        Intrinsics.checkNotNullParameter(permissionItemClickCallback, "permissionItemClickCallback");
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        this.a = binding;
        this.b = permissionItemClickCallback;
        this.c = permissions;
        this.d = z;
        this.itemView.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 14));
    }
}
