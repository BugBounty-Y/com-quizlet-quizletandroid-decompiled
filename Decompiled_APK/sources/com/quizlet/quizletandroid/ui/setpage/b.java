package com.quizlet.quizletandroid.ui.setpage;

import android.app.Dialog;
import android.os.Bundle;
import android.view.View;
import com.google.android.material.bottomsheet.i;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class b extends i {
    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        Intrinsics.checkNotNullExpressionValue(dialogK, "onCreateDialog(...)");
        dialogK.setContentView(View.inflate(getContext(), R.layout.fragment_set_edit_add_image_bottomsheet, null));
        View viewFindViewById = dialogK.findViewById(R.id.captureImageWithCamera);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "findViewById(...)");
        viewFindViewById.setOnClickListener(new com.braze.ui.inappmessage.views.a(25, this, a.a));
        View viewFindViewById2 = dialogK.findViewById(R.id.openImageFromGallery);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById2, "findViewById(...)");
        viewFindViewById2.setOnClickListener(new com.braze.ui.inappmessage.views.a(25, this, a.b));
        return dialogK;
    }
}
