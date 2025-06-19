package com.quizlet.quizletandroid.ui.setcreation.viewholders;

import android.view.View;
import android.widget.LinearLayout;
import androidx.appcompat.widget.C0076c;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.F0;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends F0 {
    public final com.quizlet.quizletandroid.ui.setcreation.adapters.f a;
    public final com.quizlet.features.infra.legacyadapter.databinding.h b;
    public final com.google.android.gms.internal.appset.e c;
    public final com.quizlet.quizletandroid.ui.login.h d;
    public final View e;
    public String f;
    public String g;

    /* JADX WARN: Illegal instructions before constructor call */
    public g(com.quizlet.quizletandroid.ui.setcreation.adapters.f adapter, com.quizlet.features.infra.legacyadapter.databinding.h itemViewBinding, com.google.android.gms.internal.appset.e scanDocumentManager, com.quizlet.quizletandroid.ui.login.h scanDocumentCtaClickListener, com.google.android.material.textfield.a fieldFocusChangeListener) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(itemViewBinding, "itemViewBinding");
        Intrinsics.checkNotNullParameter(scanDocumentManager, "scanDocumentManager");
        Intrinsics.checkNotNullParameter(scanDocumentCtaClickListener, "scanDocumentCtaClickListener");
        Intrinsics.checkNotNullParameter(fieldFocusChangeListener, "fieldFocusChangeListener");
        ConstraintLayout constraintLayout = (ConstraintLayout) itemViewBinding.e;
        super(constraintLayout);
        this.a = adapter;
        this.b = itemViewBinding;
        this.c = scanDocumentManager;
        this.d = scanDocumentCtaClickListener;
        View editSetScanDocumentTooltipContainer = ((com.quizlet.features.infra.legacyadapter.databinding.f) itemViewBinding.f).d;
        Intrinsics.checkNotNullExpressionValue(editSetScanDocumentTooltipContainer, "editSetScanDocumentTooltipContainer");
        this.e = editSetScanDocumentTooltipContainer;
        constraintLayout.setOnTouchListener(new com.amazon.aps.ads.util.adview.d(this, 5));
        this.f = "";
        this.g = "";
        e().e(new e(this, 0));
        c().e(new e(this, 1));
        final int i = 0;
        d().setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewholders.d
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i) {
                    case 0:
                        g gVar = this.b;
                        gVar.a.w.a.z("ocr_tap_scan_button");
                        assistantMode.refactored.a.p(((com.quizlet.scandocument.ui.d) gVar.c.b).a, "PREF_SEEN_SCAN_DOCUMENT_TOOLTIP", true);
                        gVar.d.j();
                        break;
                    case 1:
                        g gVar2 = this.b;
                        QTextView editSetAddDescButton = (QTextView) gVar2.b.b;
                        Intrinsics.checkNotNullExpressionValue(editSetAddDescButton, "editSetAddDescButton");
                        editSetAddDescButton.setVisibility(8);
                        gVar2.c().setVisibility(0);
                        gVar2.c().requestFocus();
                        break;
                    case 2:
                        g gVar3 = this.b;
                        gVar3.f();
                        gVar3.d.j();
                        break;
                    default:
                        g gVar4 = this.b;
                        gVar4.f();
                        gVar4.d.j();
                        break;
                }
            }
        });
        QTextView editSetAddDescButton = (QTextView) itemViewBinding.b;
        Intrinsics.checkNotNullExpressionValue(editSetAddDescButton, "editSetAddDescButton");
        final int i2 = 1;
        editSetAddDescButton.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewholders.d
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i2) {
                    case 0:
                        g gVar = this.b;
                        gVar.a.w.a.z("ocr_tap_scan_button");
                        assistantMode.refactored.a.p(((com.quizlet.scandocument.ui.d) gVar.c.b).a, "PREF_SEEN_SCAN_DOCUMENT_TOOLTIP", true);
                        gVar.d.j();
                        break;
                    case 1:
                        g gVar2 = this.b;
                        QTextView editSetAddDescButton2 = (QTextView) gVar2.b.b;
                        Intrinsics.checkNotNullExpressionValue(editSetAddDescButton2, "editSetAddDescButton");
                        editSetAddDescButton2.setVisibility(8);
                        gVar2.c().setVisibility(0);
                        gVar2.c().requestFocus();
                        break;
                    case 2:
                        g gVar3 = this.b;
                        gVar3.f();
                        gVar3.d.j();
                        break;
                    default:
                        g gVar4 = this.b;
                        gVar4.f();
                        gVar4.d.j();
                        break;
                }
            }
        });
        final int i3 = 2;
        editSetScanDocumentTooltipContainer.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewholders.d
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i3) {
                    case 0:
                        g gVar = this.b;
                        gVar.a.w.a.z("ocr_tap_scan_button");
                        assistantMode.refactored.a.p(((com.quizlet.scandocument.ui.d) gVar.c.b).a, "PREF_SEEN_SCAN_DOCUMENT_TOOLTIP", true);
                        gVar.d.j();
                        break;
                    case 1:
                        g gVar2 = this.b;
                        QTextView editSetAddDescButton2 = (QTextView) gVar2.b.b;
                        Intrinsics.checkNotNullExpressionValue(editSetAddDescButton2, "editSetAddDescButton");
                        editSetAddDescButton2.setVisibility(8);
                        gVar2.c().setVisibility(0);
                        gVar2.c().requestFocus();
                        break;
                    case 2:
                        g gVar3 = this.b;
                        gVar3.f();
                        gVar3.d.j();
                        break;
                    default:
                        g gVar4 = this.b;
                        gVar4.f();
                        gVar4.d.j();
                        break;
                }
            }
        });
        final int i4 = 3;
        ((QButton) editSetScanDocumentTooltipContainer.findViewById(R.id.scan_document_tooltip_button)).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewholders.d
            public final /* synthetic */ g b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                switch (i4) {
                    case 0:
                        g gVar = this.b;
                        gVar.a.w.a.z("ocr_tap_scan_button");
                        assistantMode.refactored.a.p(((com.quizlet.scandocument.ui.d) gVar.c.b).a, "PREF_SEEN_SCAN_DOCUMENT_TOOLTIP", true);
                        gVar.d.j();
                        break;
                    case 1:
                        g gVar2 = this.b;
                        QTextView editSetAddDescButton2 = (QTextView) gVar2.b.b;
                        Intrinsics.checkNotNullExpressionValue(editSetAddDescButton2, "editSetAddDescButton");
                        editSetAddDescButton2.setVisibility(8);
                        gVar2.c().setVisibility(0);
                        gVar2.c().requestFocus();
                        break;
                    case 2:
                        g gVar3 = this.b;
                        gVar3.f();
                        gVar3.d.j();
                        break;
                    default:
                        g gVar4 = this.b;
                        gVar4.f();
                        gVar4.d.j();
                        break;
                }
            }
        });
        e().c(fieldFocusChangeListener);
        c().c(new com.google.android.material.textfield.a(this, 6));
        c().c(fieldFocusChangeListener);
    }

    public final QFormField c() {
        QFormField editSetDescriptionField = (QFormField) this.b.d;
        Intrinsics.checkNotNullExpressionValue(editSetDescriptionField, "editSetDescriptionField");
        return editSetDescriptionField;
    }

    public final LinearLayout d() {
        LinearLayout editSetScanDocumentContainer = (LinearLayout) ((com.quizlet.features.infra.legacyadapter.databinding.f) this.b.f).c;
        Intrinsics.checkNotNullExpressionValue(editSetScanDocumentContainer, "editSetScanDocumentContainer");
        return editSetScanDocumentContainer;
    }

    public final QFormField e() {
        QFormField editSetTitleField = (QFormField) this.b.c;
        Intrinsics.checkNotNullExpressionValue(editSetTitleField, "editSetTitleField");
        return editSetTitleField;
    }

    public final void f() {
        if (d().getVisibility() == 0) {
            View view = this.e;
            if (view.getVisibility() == 0) {
                ((com.quizlet.scandocument.ui.d) this.c.b).a.edit().putBoolean("PREF_SEEN_SCAN_DOCUMENT_TOOLTIP", true).apply();
                view.animate().alpha(DefinitionKt.NO_Float_VALUE).setDuration(500L).setListener(new C0076c(this, 13)).start();
            }
        }
    }

    public final void g() {
        QTextView editSetAddDescButton = (QTextView) this.b.b;
        Intrinsics.checkNotNullExpressionValue(editSetAddDescButton, "editSetAddDescButton");
        editSetAddDescButton.setVisibility(this.g.length() > 0 ? 8 : 0);
        c().setVisibility(this.g.length() == 0 ? 8 : 0);
    }
}
