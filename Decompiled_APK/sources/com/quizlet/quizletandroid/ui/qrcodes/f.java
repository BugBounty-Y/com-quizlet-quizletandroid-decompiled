package com.quizlet.quizletandroid.ui.qrcodes;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class f extends a<d0> {
    public static final String C;
    public e B;

    static {
        String simpleName = f.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        C = simpleName;
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment
    public final androidx.viewbinding.a Q(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.qlive_qrcode_onboarding_alert, viewGroup, false);
        int i = R.id.btnContinue;
        QButton qButton = (QButton) AbstractC3375o2.c(R.id.btnContinue, viewInflate);
        if (qButton != null) {
            i = R.id.btnEnterManual;
            QButton qButton2 = (QButton) AbstractC3375o2.c(R.id.btnEnterManual, viewInflate);
            if (qButton2 != null) {
                i = R.id.qrCodeGraphic;
                if (((ImageView) AbstractC3375o2.c(R.id.qrCodeGraphic, viewInflate)) != null) {
                    i = R.id.qrDescription;
                    if (((QTextView) AbstractC3375o2.c(R.id.qrDescription, viewInflate)) != null) {
                        i = R.id.qrTitle;
                        if (((QTextView) AbstractC3375o2.c(R.id.qrTitle, viewInflate)) != null) {
                            d0 d0Var = new d0((ConstraintLayout) viewInflate, qButton, qButton2);
                            Intrinsics.checkNotNullExpressionValue(d0Var, "inflate(...)");
                            return d0Var;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.quizlet.quizletandroid.ui.qrcodes.a, com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        super.onAttach(context);
        if (!(context instanceof e)) {
            throw new IllegalStateException("Invalid callback: ".concat(context.getClass().getSimpleName()));
        }
        this.B = (e) context;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        d0 d0Var = (d0) P();
        final int i = 0;
        d0Var.b.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.qrcodes.d
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i) {
                    case 0:
                        f fVar = this.b;
                        e eVar = fVar.B;
                        if (eVar == null) {
                            Intrinsics.m("callback");
                            throw null;
                        }
                        ((QLiveQrCodeReaderActivity) eVar).b0();
                        fVar.H(false, false);
                        return;
                    default:
                        f fVar2 = this.b;
                        e eVar2 = fVar2.B;
                        if (eVar2 == null) {
                            Intrinsics.m("callback");
                            throw null;
                        }
                        ((QLiveQrCodeReaderActivity) eVar2).d0();
                        fVar2.H(false, false);
                        return;
                }
            }
        });
        d0 d0Var2 = (d0) P();
        final int i2 = 1;
        d0Var2.c.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.qrcodes.d
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i2) {
                    case 0:
                        f fVar = this.b;
                        e eVar = fVar.B;
                        if (eVar == null) {
                            Intrinsics.m("callback");
                            throw null;
                        }
                        ((QLiveQrCodeReaderActivity) eVar).b0();
                        fVar.H(false, false);
                        return;
                    default:
                        f fVar2 = this.b;
                        e eVar2 = fVar2.B;
                        if (eVar2 == null) {
                            Intrinsics.m("callback");
                            throw null;
                        }
                        ((QLiveQrCodeReaderActivity) eVar2).d0();
                        fVar2.H(false, false);
                        return;
                }
            }
        });
    }
}
