package com.quizlet.assembly.widgets;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AssemblyBadge extends QTextView {
    public a a;
    public final int b;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyBadge(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @NotNull
    public final a getVariant() {
        return this.a;
    }

    public final void h() {
        int iOrdinal = this.a.ordinal();
        if (iOrdinal == 0) {
            Context context = getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            setTextColor(com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyDefaultBadgeText));
            return;
        }
        if (iOrdinal == 1 || iOrdinal == 2) {
            if (this.a == a.d) {
                setAlpha(0.6f);
            }
            Context context2 = getContext();
            Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
            setTextColor(com.quizlet.themes.extensions.a.a(context2, R.attr.AssemblyIndigoBadgeText));
            setBackgroundResource(R.drawable.radius_small_indigo_bg);
            return;
        }
        if (iOrdinal == 3) {
            Context context3 = getContext();
            Intrinsics.checkNotNullExpressionValue(context3, "getContext(...)");
            setTextColor(com.quizlet.themes.extensions.a.a(context3, R.attr.AssemblyYellowBadgeText));
            setBackgroundResource(R.drawable.radius_small_yellow_bg);
            return;
        }
        if (iOrdinal != 4) {
            throw new NoWhenBranchMatchedException();
        }
        Context context4 = getContext();
        Intrinsics.checkNotNullExpressionValue(context4, "getContext(...)");
        setTextColor(com.quizlet.themes.extensions.a.a(context4, R.attr.AssemblyWhiteBadgeText));
        setBackgroundResource(R.drawable.radius_small_white_bg);
    }

    public final void setVariant(@NotNull a value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.a = value;
        h();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyBadge(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AssemblyBadge(Context context, AttributeSet attributeSet, int i) {
        a aVar = null;
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        int i2 = 0;
        super(context, attributeSet, 0);
        this.a = a.c;
        this.b = getResources().getDimensionPixelOffset(R.dimen.spacing_xxsmall);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.quizlet.assembly.a.a);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        try {
            int i3 = typedArrayObtainStyledAttributes.getInt(0, 0);
            a.b.getClass();
            a[] aVarArrValues = a.values();
            int length = aVarArrValues.length;
            while (true) {
                if (i2 >= length) {
                    break;
                }
                a aVar2 = aVarArrValues[i2];
                if (aVar2.a == i3) {
                    aVar = aVar2;
                    break;
                }
                i2++;
            }
            if (aVar != null) {
                setVariant(aVar);
                typedArrayObtainStyledAttributes.recycle();
                int i4 = this.b;
                setPadding(i4, i4, i4, i4);
                setTextAppearance(context, R.style.SubHeader_S5);
                h();
                return;
            }
            throw new IllegalArgumentException("Invalid AssemblyBadgeVariant");
        } catch (Throwable th) {
            typedArrayObtainStyledAttributes.recycle();
            throw th;
        }
    }
}
