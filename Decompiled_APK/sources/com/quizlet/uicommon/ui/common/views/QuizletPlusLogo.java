package com.quizlet.uicommon.ui.common.views;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.databinding.b;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.ui.states.a;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletPlusLogo extends LinearLayout {
    public final b a;
    public a b;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QuizletPlusLogo(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public final void a() {
        int iOrdinal = this.b.ordinal();
        b bVar = this.a;
        if (iOrdinal == 0) {
            QTextView forTeachers = (QTextView) bVar.c;
            Intrinsics.checkNotNullExpressionValue(forTeachers, "forTeachers");
            forTeachers.setVisibility(8);
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            QTextView forTeachers2 = (QTextView) bVar.c;
            Intrinsics.checkNotNullExpressionValue(forTeachers2, "forTeachers");
            forTeachers2.setVisibility(0);
            if (getResources().getBoolean(R.bool.invert_teacher_logo_subtitle)) {
                removeView((QTextView) bVar.c);
                addView((QTextView) bVar.c, 0);
            }
        }
    }

    @NotNull
    public final a getLogoVariant() {
        return this.b;
    }

    public final void setLogoVariant(@NotNull a value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.b = value;
        a();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QuizletPlusLogo(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public QuizletPlusLogo(Context context, AttributeSet attributeSet, int i) {
        a aVar = null;
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        LayoutInflater.from(context).inflate(R.layout.logo_quizlet_plus, this);
        int i2 = R.id.forTeachers;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.forTeachers, this);
        if (qTextView != null) {
            i2 = R.id.quizletPlusLogo;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.quizletPlusLogo, this);
            if (imageView != null) {
                b bVar = new b(this, qTextView, imageView, 7);
                Intrinsics.checkNotNullExpressionValue(bVar, "inflate(...)");
                this.a = bVar;
                this.b = a.c;
                setOrientation(1);
                int[] QuizletPlusLogo = com.quizlet.quizletandroid.ui.common.a.d;
                Intrinsics.checkNotNullExpressionValue(QuizletPlusLogo, "QuizletPlusLogo");
                TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, QuizletPlusLogo, 0, 0);
                com.quizlet.quizletandroid.logging.initializer.a aVar2 = a.b;
                int i3 = typedArrayObtainStyledAttributes.getInt(1, 0);
                aVar2.getClass();
                a[] aVarArrValues = a.values();
                int length = aVarArrValues.length;
                int i4 = 0;
                while (true) {
                    if (i4 >= length) {
                        break;
                    }
                    a aVar3 = aVarArrValues[i4];
                    if (aVar3.a == i3) {
                        aVar = aVar3;
                        break;
                    }
                    i4++;
                }
                if (aVar != null) {
                    setLogoVariant(aVar);
                    ImageView quizletPlusLogo = (ImageView) this.a.d;
                    Intrinsics.checkNotNullExpressionValue(quizletPlusLogo, "quizletPlusLogo");
                    ViewGroup.LayoutParams layoutParams = quizletPlusLogo.getLayoutParams();
                    if (layoutParams != null) {
                        LinearLayout.LayoutParams layoutParams2 = (LinearLayout.LayoutParams) layoutParams;
                        layoutParams2.height = typedArrayObtainStyledAttributes.getLayoutDimension(0, typedArrayObtainStyledAttributes.getResources().getDimensionPixelSize(R.dimen.ref_size_medium));
                        quizletPlusLogo.setLayoutParams(layoutParams2);
                        typedArrayObtainStyledAttributes.recycle();
                        a();
                        return;
                    }
                    throw new NullPointerException("null cannot be cast to non-null type android.widget.LinearLayout.LayoutParams");
                }
                throw new IllegalArgumentException("Invalid QuizletPlusLogoVariant");
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(i2)));
    }
}
