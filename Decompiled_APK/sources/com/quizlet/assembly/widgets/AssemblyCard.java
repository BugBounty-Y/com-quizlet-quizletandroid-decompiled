package com.quizlet.assembly.widgets;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AssemblyCard extends CardView {
    public final com.quizlet.assembly.databinding.b h;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyCard(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyCard(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AssemblyCard(Context context, AttributeSet attributeSet, int i) {
        int i2 = 0;
        b bVar = null;
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        LayoutInflater.from(context).inflate(R.layout.view_assembly_card, this);
        View viewC = AbstractC3375o2.c(R.id.bottomBar, this);
        if (viewC != null) {
            com.quizlet.assembly.databinding.b bVar2 = new com.quizlet.assembly.databinding.b(0, viewC, this);
            Intrinsics.checkNotNullExpressionValue(bVar2, "inflate(...)");
            this.h = bVar2;
            com.quizlet.shared.usecase.folderstudymaterials.b bVar3 = b.b;
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.quizlet.assembly.a.b);
            Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
            try {
                int i3 = typedArrayObtainStyledAttributes.getInt(0, 0);
                b.b.getClass();
                b[] bVarArrValues = b.values();
                int length = bVarArrValues.length;
                while (true) {
                    if (i2 >= length) {
                        break;
                    }
                    b bVar4 = bVarArrValues[i2];
                    if (bVar4.a == i3) {
                        bVar = bVar4;
                        break;
                    }
                    i2++;
                }
                if (bVar != null) {
                    int iOrdinal = bVar.ordinal();
                    if (iOrdinal == 0) {
                        setCardElevation(getResources().getDimensionPixelOffset(R.dimen.ref_spacing_xsmall));
                        setRadius(getResources().getDimensionPixelOffset(R.dimen.ref_radius_medium));
                        setBackgroundResource(R.drawable.assembly_card_small_background);
                        this.h.c.getLayoutParams().height = getResources().getDimensionPixelOffset(R.dimen.spacing_xxsmall);
                    } else if (iOrdinal == 1) {
                        setCardElevation(getResources().getDimensionPixelOffset(R.dimen.ref_spacing_small));
                        setRadius(getResources().getDimensionPixelOffset(R.dimen.ref_radius_large));
                        setBackgroundResource(R.drawable.assembly_card_medium_background);
                        this.h.c.getLayoutParams().height = getResources().getDimensionPixelOffset(R.dimen.ref_spacing_xsmall);
                    } else {
                        throw new NoWhenBranchMatchedException();
                    }
                    typedArrayObtainStyledAttributes.recycle();
                    return;
                }
                throw new IllegalArgumentException("Invalid AssemblyCardVariant");
            } catch (Throwable th) {
                typedArrayObtainStyledAttributes.recycle();
                throw th;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(R.id.bottomBar)));
    }
}
