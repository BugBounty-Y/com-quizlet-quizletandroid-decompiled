package com.quizlet.uicommon.ui.common.widgets;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.widget.FrameLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QRadioButton;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QSegmentedControl extends FrameLayout {
    public static final /* synthetic */ int b = 0;
    public final androidx.viewbinding.a a;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QSegmentedControl(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final RadioButton getMRadioButtonLeft() {
        androidx.viewbinding.a aVar = this.a;
        if (aVar instanceof com.quizlet.quizletandroid.ui.common.databinding.g) {
            QRadioButton widgetSegmentedControlLeft = ((com.quizlet.quizletandroid.ui.common.databinding.g) aVar).b;
            Intrinsics.checkNotNullExpressionValue(widgetSegmentedControlLeft, "widgetSegmentedControlLeft");
            return widgetSegmentedControlLeft;
        }
        if (!(aVar instanceof com.quizlet.quizletandroid.ui.common.databinding.h)) {
            throw new IllegalArgumentException("segmented control layout not implemented");
        }
        QRadioButton widgetSegmentedControlLeft2 = ((com.quizlet.quizletandroid.ui.common.databinding.h) aVar).b;
        Intrinsics.checkNotNullExpressionValue(widgetSegmentedControlLeft2, "widgetSegmentedControlLeft");
        return widgetSegmentedControlLeft2;
    }

    private final RadioButton getMRadioButtonMiddle() {
        androidx.viewbinding.a aVar = this.a;
        if (aVar instanceof com.quizlet.quizletandroid.ui.common.databinding.g) {
            QRadioButton widgetSegmentedControlMiddle = ((com.quizlet.quizletandroid.ui.common.databinding.g) aVar).c;
            Intrinsics.checkNotNullExpressionValue(widgetSegmentedControlMiddle, "widgetSegmentedControlMiddle");
            return widgetSegmentedControlMiddle;
        }
        if (!(aVar instanceof com.quizlet.quizletandroid.ui.common.databinding.h)) {
            throw new IllegalArgumentException("segmented control layout not implemented");
        }
        QRadioButton widgetSegmentedControlMiddle2 = ((com.quizlet.quizletandroid.ui.common.databinding.h) aVar).c;
        Intrinsics.checkNotNullExpressionValue(widgetSegmentedControlMiddle2, "widgetSegmentedControlMiddle");
        return widgetSegmentedControlMiddle2;
    }

    private final RadioButton getMRadioButtonRight() {
        androidx.viewbinding.a aVar = this.a;
        if (aVar instanceof com.quizlet.quizletandroid.ui.common.databinding.g) {
            QRadioButton widgetSegmentedControlRight = ((com.quizlet.quizletandroid.ui.common.databinding.g) aVar).e;
            Intrinsics.checkNotNullExpressionValue(widgetSegmentedControlRight, "widgetSegmentedControlRight");
            return widgetSegmentedControlRight;
        }
        if (!(aVar instanceof com.quizlet.quizletandroid.ui.common.databinding.h)) {
            throw new IllegalArgumentException("segmented control layout not implemented");
        }
        QRadioButton widgetSegmentedControlRight2 = ((com.quizlet.quizletandroid.ui.common.databinding.h) aVar).e;
        Intrinsics.checkNotNullExpressionValue(widgetSegmentedControlRight2, "widgetSegmentedControlRight");
        return widgetSegmentedControlRight2;
    }

    private final RadioGroup getMRadioGroup() {
        androidx.viewbinding.a aVar = this.a;
        if (aVar instanceof com.quizlet.quizletandroid.ui.common.databinding.g) {
            RadioGroup widgetSegmentedControlRadiogroup = ((com.quizlet.quizletandroid.ui.common.databinding.g) aVar).d;
            Intrinsics.checkNotNullExpressionValue(widgetSegmentedControlRadiogroup, "widgetSegmentedControlRadiogroup");
            return widgetSegmentedControlRadiogroup;
        }
        if (!(aVar instanceof com.quizlet.quizletandroid.ui.common.databinding.h)) {
            throw new IllegalArgumentException("segmented control layout not implemented");
        }
        RadioGroup widgetSegmentedControlRadiogroup2 = ((com.quizlet.quizletandroid.ui.common.databinding.h) aVar).d;
        Intrinsics.checkNotNullExpressionValue(widgetSegmentedControlRadiogroup2, "widgetSegmentedControlRadiogroup");
        return widgetSegmentedControlRadiogroup2;
    }

    private final void setButtonsContentDescription(TypedArray typedArray) {
        String string = typedArray.getString(0);
        String string2 = typedArray.getString(2);
        String string3 = typedArray.getString(4);
        setLeftButtonContentDescription(string);
        setMiddleButtonContentDescription(string2);
        setRightButtonContentDescription(string3);
    }

    private final void setButtonsText(TypedArray typedArray) {
        String string = typedArray.getString(1);
        String string2 = typedArray.getString(3);
        String string3 = typedArray.getString(5);
        setLeftButtonText(string);
        setMiddleButtonText(string2);
        setRightButtonText(string3);
    }

    @NotNull
    public final i getCheckedSegment() {
        return getMRadioButtonLeft().isChecked() ? i.a : getMRadioButtonMiddle().isChecked() ? i.b : i.c;
    }

    public final void setCheckedSegment(@NotNull i segment) {
        Intrinsics.checkNotNullParameter(segment, "segment");
        int iOrdinal = segment.ordinal();
        if (iOrdinal == 0) {
            getMRadioButtonLeft().setChecked(true);
            return;
        }
        if (iOrdinal != 1) {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            getMRadioButtonRight().setChecked(true);
        } else if (getMRadioButtonMiddle().getVisibility() == 0) {
            getMRadioButtonMiddle().setChecked(true);
        }
    }

    public final void setLeftButtonContentDescription(CharSequence charSequence) {
        getMRadioButtonLeft().setContentDescription(charSequence);
    }

    public final void setLeftButtonText(CharSequence charSequence) {
        getMRadioButtonLeft().setText(charSequence);
    }

    public final void setMiddleButtonContentDescription(CharSequence charSequence) {
        getMRadioButtonMiddle().setContentDescription(charSequence);
    }

    public final void setMiddleButtonText(CharSequence charSequence) {
        if (charSequence == null && getMRadioButtonMiddle().isChecked()) {
            setCheckedSegment(i.a);
        }
        getMRadioButtonMiddle().setVisibility(charSequence != null ? 0 : 8);
        getMRadioButtonMiddle().setText(charSequence);
    }

    public final void setOnCheckedChangedListener(@NotNull final h listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        getMRadioGroup().setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() { // from class: com.quizlet.uicommon.ui.common.widgets.g
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public final void onCheckedChanged(RadioGroup radioGroup, int i) {
                int i2 = QSegmentedControl.b;
                listener.b(this.getCheckedSegment());
            }
        });
    }

    public final void setRightButtonContentDescription(CharSequence charSequence) {
        getMRadioButtonRight().setContentDescription(charSequence);
    }

    public final void setRightButtonText(CharSequence charSequence) {
        getMRadioButtonRight().setText(charSequence);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QSegmentedControl(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public QSegmentedControl(Context context, AttributeSet attributeSet, int i) {
        QSegmentedControl qSegmentedControl;
        androidx.viewbinding.a aVarA;
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        if (attributeSet == null) {
            this.a = com.quizlet.quizletandroid.ui.common.databinding.g.a(LayoutInflater.from(context), this);
            return;
        }
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.quizlet.quizletandroid.ui.common.a.c);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        if (typedArrayObtainStyledAttributes.getResourceId(6, R.layout.widget_segmented_control) == R.layout.widget_segmented_control_v3) {
            LayoutInflater.from(context).inflate(R.layout.widget_segmented_control_v3, this);
            int i2 = R.id.widget_segmented_control_left;
            QRadioButton qRadioButton = (QRadioButton) AbstractC3375o2.c(R.id.widget_segmented_control_left, this);
            if (qRadioButton != null) {
                i2 = R.id.widget_segmented_control_middle;
                QRadioButton qRadioButton2 = (QRadioButton) AbstractC3375o2.c(R.id.widget_segmented_control_middle, this);
                if (qRadioButton2 != null) {
                    i2 = R.id.widget_segmented_control_radiogroup;
                    RadioGroup radioGroup = (RadioGroup) AbstractC3375o2.c(R.id.widget_segmented_control_radiogroup, this);
                    if (radioGroup != null) {
                        i2 = R.id.widget_segmented_control_right;
                        QRadioButton qRadioButton3 = (QRadioButton) AbstractC3375o2.c(R.id.widget_segmented_control_right, this);
                        if (qRadioButton3 != null) {
                            qSegmentedControl = this;
                            aVarA = new com.quizlet.quizletandroid.ui.common.databinding.h(qSegmentedControl, qRadioButton, qRadioButton2, radioGroup, qRadioButton3);
                            Intrinsics.checkNotNullExpressionValue(aVarA, "inflate(...)");
                        }
                    }
                }
            }
            throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(i2)));
        }
        qSegmentedControl = this;
        aVarA = com.quizlet.quizletandroid.ui.common.databinding.g.a(LayoutInflater.from(context), this);
        Intrinsics.checkNotNullExpressionValue(aVarA, "inflate(...)");
        qSegmentedControl.a = aVarA;
        setButtonsText(typedArrayObtainStyledAttributes);
        setButtonsContentDescription(typedArrayObtainStyledAttributes);
        typedArrayObtainStyledAttributes.recycle();
        getMRadioButtonLeft().setChecked(true);
    }
}
