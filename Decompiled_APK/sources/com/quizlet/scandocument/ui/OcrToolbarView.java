package com.quizlet.scandocument.ui;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageButton;
import android.widget.RadioGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.explanations.feedback.ui.fragments.f;
import com.quizlet.infra.legacysyncengine.net.request.g;
import com.quizlet.partskit.widgets.QRadioButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.scandocument.model.EnumC4781a;
import com.quizlet.scandocument.model.k;
import com.quizlet.scandocument.model.q;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
@SuppressLint({"CheckResult"})
/* loaded from: classes3.dex */
public final class OcrToolbarView extends ConstraintLayout {
    public static final /* synthetic */ int D = 0;
    public final RadioGroup A;
    public final ImageButton B;
    public q C;
    public com.quizlet.scandocument.model.b q;
    public EnumC4781a r;
    public QRadioButton s;
    public QRadioButton t;
    public final io.reactivex.rxjava3.subjects.d u;
    public final io.reactivex.rxjava3.subjects.d v;
    public final io.reactivex.rxjava3.subjects.d w;
    public final io.reactivex.rxjava3.subjects.d x;
    public final ImageButton y;
    public final ImageButton z;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public OcrToolbarView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @NotNull
    public final EnumC4781a getCurrentInputMethod() {
        return this.r;
    }

    @NotNull
    public final com.quizlet.scandocument.model.b getCurrentInteractionMode() {
        return this.q;
    }

    @NotNull
    public final QRadioButton getInteractionModeHighlightButton() {
        return this.s;
    }

    @NotNull
    public final QRadioButton getInteractionModeMoveButton() {
        return this.t;
    }

    public final void p() {
        EnumC4781a enumC4781a;
        int iOrdinal = this.r.ordinal();
        if (iOrdinal == 0) {
            enumC4781a = EnumC4781a.b;
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            enumC4781a = EnumC4781a.a;
        }
        this.r = enumC4781a;
        this.u.b(enumC4781a);
    }

    public final void q(EnumC4781a inputMethod) {
        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
        EnumC4781a enumC4781a = EnumC4781a.a;
        boolean z = inputMethod == enumC4781a;
        ImageButton imageButton = this.y;
        imageButton.setEnabled(z);
        boolean z2 = inputMethod != enumC4781a;
        ImageButton imageButton2 = this.z;
        imageButton2.setEnabled(z2);
        int i = R.attr.ocrToolbarControlIconColorInverse;
        int i2 = inputMethod == enumC4781a ? R.attr.ocrToolbarControlIconColor : R.attr.ocrToolbarControlIconColorInverse;
        if (inputMethod != enumC4781a) {
            i = R.attr.ocrToolbarControlIconColor;
        }
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        Drawable drawableC = com.quizlet.themes.extensions.a.c(context, R.drawable.ic_sys_scan, i2);
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        Drawable drawableC2 = com.quizlet.themes.extensions.a.c(context2, R.drawable.ic_sys_keyboard, i);
        imageButton2.setImageDrawable(drawableC);
        imageButton.setImageDrawable(drawableC2);
        r();
    }

    public final void r() {
        boolean z = this.r == EnumC4781a.a && (this.C instanceof k);
        RadioGroup radioGroup = this.A;
        radioGroup.setOnCheckedChangeListener(null);
        QRadioButton qRadioButton = this.s;
        qRadioButton.setEnabled(z);
        qRadioButton.setChecked(z);
        QRadioButton qRadioButton2 = this.t;
        qRadioButton2.setEnabled(z);
        qRadioButton2.setChecked(!z);
        radioGroup.setOnCheckedChangeListener(new f(this, 1));
    }

    public final void setCurrentInputMethod(@NotNull EnumC4781a enumC4781a) {
        Intrinsics.checkNotNullParameter(enumC4781a, "<set-?>");
        this.r = enumC4781a;
    }

    public final void setCurrentInteractionMode(@NotNull com.quizlet.scandocument.model.b bVar) {
        Intrinsics.checkNotNullParameter(bVar, "<set-?>");
        this.q = bVar;
    }

    public final void setInteractionModeHighlightButton(@NotNull QRadioButton qRadioButton) {
        Intrinsics.checkNotNullParameter(qRadioButton, "<set-?>");
        this.s = qRadioButton;
    }

    public final void setInteractionModeMoveButton(@NotNull QRadioButton qRadioButton) {
        Intrinsics.checkNotNullParameter(qRadioButton, "<set-?>");
        this.t = qRadioButton;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public OcrToolbarView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public OcrToolbarView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        this.q = com.quizlet.scandocument.model.b.a;
        EnumC4781a enumC4781a = EnumC4781a.a;
        this.r = enumC4781a;
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.u = dVarZ;
        io.reactivex.rxjava3.subjects.d dVarZ2 = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ2, "create(...)");
        this.v = dVarZ2;
        io.reactivex.rxjava3.subjects.d dVarZ3 = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ3, "create(...)");
        this.w = dVarZ3;
        io.reactivex.rxjava3.subjects.d dVarZ4 = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ4, "create(...)");
        this.x = dVarZ4;
        View viewInflate = View.inflate(context, R.layout.view_ocr_toolbar, this);
        this.s = (QRadioButton) viewInflate.findViewById(R.id.interactionModeHighlight);
        this.t = (QRadioButton) viewInflate.findViewById(R.id.interactionModeMove);
        ImageButton imageButton = (ImageButton) viewInflate.findViewById(R.id.keyboardInputMethodImageButton);
        this.y = imageButton;
        ImageButton imageButton2 = (ImageButton) viewInflate.findViewById(R.id.ocrInputMethodImageButton);
        this.z = imageButton2;
        this.A = (RadioGroup) viewInflate.findViewById(R.id.interactionModeRadioGroup);
        ImageButton imageButton3 = (ImageButton) viewInflate.findViewById(R.id.addCardButton);
        this.B = imageButton3;
        c cVar = new c(this, 0);
        g gVar = io.reactivex.rxjava3.internal.functions.d.e;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        dVarZ.u(cVar, gVar, bVar);
        dVarZ.b(enumC4781a);
        imageButton3.setEnabled(false);
        dVarZ3.u(new c(this, 1), gVar, bVar);
        final int i2 = 0;
        imageButton3.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.scandocument.ui.a
            public final /* synthetic */ OcrToolbarView b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                OcrToolbarView ocrToolbarView = this.b;
                switch (i2) {
                    case 0:
                        ocrToolbarView.x.b(Unit.a);
                        break;
                    case 1:
                        int i3 = OcrToolbarView.D;
                        ocrToolbarView.p();
                        break;
                    default:
                        int i4 = OcrToolbarView.D;
                        ocrToolbarView.p();
                        break;
                }
            }
        });
        final int i3 = 1;
        imageButton.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.scandocument.ui.a
            public final /* synthetic */ OcrToolbarView b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                OcrToolbarView ocrToolbarView = this.b;
                switch (i3) {
                    case 0:
                        ocrToolbarView.x.b(Unit.a);
                        break;
                    case 1:
                        int i32 = OcrToolbarView.D;
                        ocrToolbarView.p();
                        break;
                    default:
                        int i4 = OcrToolbarView.D;
                        ocrToolbarView.p();
                        break;
                }
            }
        });
        final int i4 = 2;
        imageButton2.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.scandocument.ui.a
            public final /* synthetic */ OcrToolbarView b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                OcrToolbarView ocrToolbarView = this.b;
                switch (i4) {
                    case 0:
                        ocrToolbarView.x.b(Unit.a);
                        break;
                    case 1:
                        int i32 = OcrToolbarView.D;
                        ocrToolbarView.p();
                        break;
                    default:
                        int i42 = OcrToolbarView.D;
                        ocrToolbarView.p();
                        break;
                }
            }
        });
    }
}
