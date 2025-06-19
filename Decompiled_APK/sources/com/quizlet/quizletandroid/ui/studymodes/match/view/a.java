package com.quizlet.quizletandroid.ui.studymodes.match.view;

import android.content.Context;
import android.content.res.TypedArray;
import androidx.core.content.res.k;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.I;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes3.dex */
public class a extends QTextView {
    public a(Context context) {
        super(context);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(null, I.c, 0, R.style.MatchPenaltyText);
        int color = typedArrayObtainStyledAttributes.getColor(2, -16777216);
        float dimension = typedArrayObtainStyledAttributes.getDimension(0, DefinitionKt.NO_Float_VALUE);
        int i = typedArrayObtainStyledAttributes.getInt(1, 0);
        typedArrayObtainStyledAttributes.recycle();
        setTextSize(dimension);
        setTextColor(color);
        setTypeface(k.a(context, com.quizlet.ui.resources.designsystem.generated.a.b), i);
    }
}
