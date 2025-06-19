package com.quizlet.quizletandroid.ui.setcreation.dialogs;

import android.app.Dialog;
import android.os.Bundle;
import android.view.View;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.setcreation.fragments.k;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class a extends DialogInterfaceOnCancelListenerC1151t {
    public k q;
    public QFormField r;
    public String s;

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        View viewInflate = View.inflate(getContext(), R.layout.dialog_set_title, null);
        QFormField qFormField = (QFormField) viewInflate.findViewById(R.id.titleField);
        this.r = qFormField;
        if (qFormField == null) {
            Intrinsics.m("titleField");
            throw null;
        }
        qFormField.setText(this.s);
        e.a aVar = new e.a(getContext());
        aVar.b = false;
        aVar.f(R.string.set_title_dialog_title);
        aVar.h = viewInflate;
        aVar.e(R.string.save, new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 17));
        aVar.d(R.string.cancel, new com.quizlet.infra.legacysyncengine.models.serializers.a(27));
        e eVarB = aVar.b();
        Intrinsics.checkNotNullExpressionValue(eVarB, "create(...)");
        return eVarB;
    }
}
