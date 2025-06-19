package com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.assembly.widgets.AssemblyBadge;
import com.quizlet.features.infra.legacyadapter.databinding.h;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ExistingAccountView extends ConstraintLayout {
    public com.quizlet.qutils.image.loading.a q;
    public final h r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ExistingAccountView(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        h hVarC = h.c(LayoutInflater.from(getContext()), this);
        Intrinsics.checkNotNullExpressionValue(hVarC, "inflate(...)");
        this.r = hVarC;
        if (isInEditMode()) {
            return;
        }
        this.q = (com.quizlet.qutils.image.loading.a) ((u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, getContext().getApplicationContext()))).s.get();
    }

    private final void setBadge(boolean z) {
        h hVar = this.r;
        if (!z) {
            ((AssemblyBadge) hVar.f).setVisibility(8);
        } else {
            ((AssemblyBadge) hVar.f).setVisibility(0);
            ((AssemblyBadge) hVar.f).setText(getResources().getString(R.string.plus));
        }
    }

    private final void setProfileImage(String str) {
        h hVar = this.r;
        if (str == null || str.length() == 0) {
            ((ImageView) hVar.c).setImageDrawable(null);
            return;
        }
        com.quizlet.data.repository.widget.b bVarP = ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) getImageLoader()).a(((ImageView) hVar.c).getContext()).p(str);
        bVarP.d();
        bVarP.o((ImageView) hVar.c);
    }

    @NotNull
    public final com.quizlet.qutils.image.loading.a getImageLoader() {
        com.quizlet.qutils.image.loading.a aVar = this.q;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("imageLoader");
        throw null;
    }

    public final void p(String username, String email, String profileImageUrl, boolean z) {
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(email, "email");
        Intrinsics.checkNotNullParameter(profileImageUrl, "profileImageUrl");
        h hVar = this.r;
        ((QTextView) hVar.d).setText(username);
        ((QTextView) hVar.b).setText(email);
        setProfileImage(profileImageUrl);
        setBadge(z);
    }

    public final void setImageLoader(@NotNull com.quizlet.qutils.image.loading.a aVar) {
        Intrinsics.checkNotNullParameter(aVar, "<set-?>");
        this.q = aVar;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ExistingAccountView(@NotNull Context context, @NotNull AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attributeSet, "attributeSet");
        h hVarC = h.c(LayoutInflater.from(getContext()), this);
        Intrinsics.checkNotNullExpressionValue(hVarC, "inflate(...)");
        this.r = hVarC;
        if (isInEditMode()) {
            return;
        }
        this.q = (com.quizlet.qutils.image.loading.a) ((u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, getContext().getApplicationContext()))).s.get();
    }
}
