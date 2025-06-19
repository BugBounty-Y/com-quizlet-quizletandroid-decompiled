package com.quizlet.assembly.widgets;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.facebook.appevents.g;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public class AssemblyPill extends ConstraintLayout {
    public c q;
    public final com.quizlet.assembly.databinding.a r;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyPill(@NotNull Context context) {
        this(context, null, 6, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @NotNull
    public final com.quizlet.assembly.databinding.a getBinding() {
        return this.r;
    }

    @NotNull
    public final String getText() {
        return this.r.c.getText().toString();
    }

    @NotNull
    public final c getVariant() {
        return this.q;
    }

    public final void p(Drawable drawable, ImageView imageView, boolean z) {
        if (z && drawable != null) {
            Context context = getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            drawable.setTint(com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyPillTextColor));
        }
        imageView.setVisibility(0);
        imageView.setImageDrawable(drawable);
    }

    public final void q(String str) {
        com.quizlet.assembly.databinding.a aVar = this.r;
        aVar.c.setText(str);
        QTextView pillText = aVar.c;
        Intrinsics.checkNotNullExpressionValue(pillText, "pillText");
        pillText.setVisibility(str == null || StringsKt.O(str) ? 8 : 0);
    }

    public final void setLeftImage(int i) {
        Drawable drawableF = g.f(getContext(), i);
        ImageView leftImage = this.r.b;
        Intrinsics.checkNotNullExpressionValue(leftImage, "leftImage");
        p(drawableF, leftImage, false);
    }

    public final void setText(@NotNull String pillText) {
        Intrinsics.checkNotNullParameter(pillText, "pillText");
        q(pillText);
    }

    public final void setVariant(@NotNull c value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.q = value;
        int iOrdinal = value.ordinal();
        com.quizlet.assembly.databinding.a aVar = this.r;
        switch (iOrdinal) {
            case 0:
                setBackgroundResource(R.drawable.assembly_pill_shape);
                QTextView qTextView = aVar.c;
                Context context = getContext();
                Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                qTextView.setTextColor(com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyPillTextColor));
                break;
            case 1:
                setBackgroundResource(R.drawable.assembly_pill_shape_coral);
                QTextView qTextView2 = aVar.c;
                Context context2 = getContext();
                Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
                qTextView2.setTextColor(com.quizlet.themes.extensions.a.a(context2, R.attr.RefColorGray800));
                break;
            case 2:
                setBackgroundResource(R.drawable.assembly_pill_shape_plus);
                QTextView qTextView3 = aVar.c;
                Context context3 = getContext();
                Intrinsics.checkNotNullExpressionValue(context3, "getContext(...)");
                qTextView3.setTextColor(com.quizlet.themes.extensions.a.a(context3, R.attr.AssemblyGray700));
                break;
            case 3:
                setBackgroundResource(R.drawable.progress_pill_mint);
                QTextView qTextView4 = aVar.c;
                Context context4 = getContext();
                Intrinsics.checkNotNullExpressionValue(context4, "getContext(...)");
                qTextView4.setTextColor(com.quizlet.themes.extensions.a.a(context4, R.attr.KnowColor));
                break;
            case 4:
                setBackgroundResource(R.drawable.progress_pill_sherbert);
                QTextView qTextView5 = aVar.c;
                Context context5 = getContext();
                Intrinsics.checkNotNullExpressionValue(context5, "getContext(...)");
                qTextView5.setTextColor(com.quizlet.themes.extensions.a.a(context5, R.attr.StillLearningColor));
                break;
            case 5:
                setBackgroundResource(R.drawable.progress_pill_gray);
                QTextView qTextView6 = aVar.c;
                Context context6 = getContext();
                Intrinsics.checkNotNullExpressionValue(context6, "getContext(...)");
                qTextView6.setTextColor(com.quizlet.themes.extensions.a.a(context6, R.attr.LeftColor));
                break;
            case 6:
                setBackgroundResource(R.drawable.assembly_pill_verified);
                QTextView qTextView7 = aVar.c;
                Context context7 = getContext();
                Intrinsics.checkNotNullExpressionValue(context7, "getContext(...)");
                qTextView7.setTextColor(com.quizlet.themes.extensions.a.a(context7, R.attr.AssemblyPillVerifiedTextColor));
                break;
            case 7:
                setBackgroundResource(R.drawable.assembly_pill_subtle);
                QTextView qTextView8 = aVar.c;
                Context context8 = getContext();
                Intrinsics.checkNotNullExpressionValue(context8, "getContext(...)");
                qTextView8.setTextColor(com.quizlet.themes.extensions.a.a(context8, R.attr.AssemblyGray700));
                break;
            case 8:
                setBackgroundResource(R.drawable.assembly_pill_callout);
                QTextView qTextView9 = aVar.c;
                Context context9 = getContext();
                Intrinsics.checkNotNullExpressionValue(context9, "getContext(...)");
                qTextView9.setTextColor(com.quizlet.themes.extensions.a.a(context9, R.attr.AssemblyGray100));
                break;
            default:
                throw new NoWhenBranchMatchedException();
        }
        setPadding((int) getResources().getDimension(R.dimen.assembly_pill_spacing), (int) getResources().getDimension(R.dimen.assembly_pill_vertical_spacing), (int) getResources().getDimension(R.dimen.assembly_pill_spacing), (int) getResources().getDimension(R.dimen.assembly_pill_vertical_spacing));
        setMinHeight((int) getResources().getDimension(R.dimen.assembly_pill_height));
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyPill(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ AssemblyPill(Context context, AttributeSet attributeSet, int i, int i2) {
        this(context, (i & 2) != 0 ? null : attributeSet, 0);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AssemblyPill(Context context, AttributeSet attributeSet, int i) {
        c cVar;
        super(context, attributeSet, 0);
        Intrinsics.checkNotNullParameter(context, "context");
        this.q = c.c;
        LayoutInflater.from(context).inflate(R.layout.assembly_pill, this);
        int i2 = R.id.leftImage;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.leftImage, this);
        if (imageView != null) {
            i2 = R.id.pillText;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.pillText, this);
            if (qTextView != null) {
                i2 = R.id.rightImage;
                ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.rightImage, this);
                if (imageView2 != null) {
                    com.quizlet.assembly.databinding.a aVar = new com.quizlet.assembly.databinding.a(this, imageView, qTextView, imageView2);
                    Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
                    this.r = aVar;
                    TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.quizlet.assembly.a.e);
                    Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
                    int i3 = typedArrayObtainStyledAttributes.getInt(3, 0);
                    c.b.getClass();
                    c[] cVarArrValues = c.values();
                    int length = cVarArrValues.length;
                    int i4 = 0;
                    while (true) {
                        if (i4 >= length) {
                            cVar = null;
                            break;
                        }
                        cVar = cVarArrValues[i4];
                        if (cVar.a == i3) {
                            break;
                        } else {
                            i4++;
                        }
                    }
                    if (cVar != null) {
                        setVariant(cVar);
                        q(typedArrayObtainStyledAttributes.getString(2));
                        boolean z = typedArrayObtainStyledAttributes.getBoolean(0, true);
                        Drawable drawable = typedArrayObtainStyledAttributes.getDrawable(1);
                        if (drawable != null) {
                            ImageView leftImage = this.r.b;
                            Intrinsics.checkNotNullExpressionValue(leftImage, "leftImage");
                            p(drawable, leftImage, z);
                        }
                        Drawable drawable2 = typedArrayObtainStyledAttributes.getDrawable(4);
                        if (drawable2 != null) {
                            ImageView rightImage = this.r.d;
                            Intrinsics.checkNotNullExpressionValue(rightImage, "rightImage");
                            p(drawable2, rightImage, z);
                        }
                        typedArrayObtainStyledAttributes.recycle();
                        return;
                    }
                    throw new IllegalArgumentException("Invalid AssemblyPillVariant");
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(i2)));
    }
}
