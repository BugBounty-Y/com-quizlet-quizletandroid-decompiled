package com.quizlet.quizletandroid.ui.setcreation;

import android.app.Dialog;
import android.os.Bundle;
import android.view.View;
import com.google.android.material.bottomsheet.h;
import com.google.android.material.bottomsheet.i;
import com.onetrust.otpublishers.headless.UI.adapter.ViewOnClickListenerC4055k;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.setcreation.fragments.ScanDocumentFragment;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class a extends i {
    public ScanDocumentFragment q;

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        Intrinsics.checkNotNullExpressionValue(dialogK, "onCreateDialog(...)");
        dialogK.setContentView(View.inflate(getContext(), R.layout.fragment_scan_document_publish_set_bottomsheet, null));
        h hVar = (h) dialogK;
        ((QTextView) hVar.findViewById(R.id.publishSet)).setOnClickListener(new ViewOnClickListenerC4055k(this, R.id.publishSet, hVar, 1));
        ((QTextView) hVar.findViewById(R.id.previewSet)).setOnClickListener(new ViewOnClickListenerC4055k(this, R.id.previewSet, hVar, 1));
        ((QTextView) hVar.findViewById(R.id.deleteSet)).setOnClickListener(new ViewOnClickListenerC4055k(this, R.id.deleteSet, hVar, 1));
        Unit unit = Unit.a;
        return dialogK;
    }
}
