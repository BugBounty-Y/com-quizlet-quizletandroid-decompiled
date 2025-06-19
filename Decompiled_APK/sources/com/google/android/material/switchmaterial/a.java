package com.google.android.material.switchmaterial;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewParent;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.view.L;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.material.internal.p;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class a extends SwitchCompat {
    public static final int[][] k1 = {new int[]{R.attr.state_enabled, R.attr.state_checked}, new int[]{R.attr.state_enabled, -16842912}, new int[]{-16842910, R.attr.state_checked}, new int[]{-16842910, -16842912}};
    public final com.google.android.material.elevation.a g1;
    public ColorStateList h1;
    public ColorStateList i1;
    public boolean j1;

    public a(@NonNull Context context) {
        this(context, null, com.quizlet.quizletandroid.R.attr.switchStyle);
    }

    private ColorStateList getMaterialThemeColorsThumbTintList() throws Resources.NotFoundException {
        if (this.h1 == null) {
            int iB = X3.b(com.quizlet.quizletandroid.R.attr.colorSurface, this);
            int iB2 = X3.b(com.quizlet.quizletandroid.R.attr.colorControlActivated, this);
            float dimension = getResources().getDimension(com.quizlet.quizletandroid.R.dimen.mtrl_switch_thumb_elevation);
            com.google.android.material.elevation.a aVar = this.g1;
            if (aVar.a) {
                float fE = DefinitionKt.NO_Float_VALUE;
                for (ViewParent parent = getParent(); parent instanceof View; parent = parent.getParent()) {
                    WeakHashMap weakHashMap = V.a;
                    fE += L.e((View) parent);
                }
                dimension += fE;
            }
            int iA = aVar.a(dimension, iB);
            this.h1 = new ColorStateList(k1, new int[]{X3.e(iB, 1.0f, iB2), iA, X3.e(iB, 0.38f, iB2), iA});
        }
        return this.h1;
    }

    private ColorStateList getMaterialThemeColorsTrackTintList() {
        if (this.i1 == null) {
            int iB = X3.b(com.quizlet.quizletandroid.R.attr.colorSurface, this);
            int iB2 = X3.b(com.quizlet.quizletandroid.R.attr.colorControlActivated, this);
            int iB3 = X3.b(com.quizlet.quizletandroid.R.attr.colorOnSurface, this);
            this.i1 = new ColorStateList(k1, new int[]{X3.e(iB, 0.54f, iB2), X3.e(iB, 0.32f, iB3), X3.e(iB, 0.12f, iB2), X3.e(iB, 0.12f, iB3)});
        }
        return this.i1;
    }

    @Override // android.widget.TextView, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.j1 && getThumbTintList() == null) {
            setThumbTintList(getMaterialThemeColorsThumbTintList());
        }
        if (this.j1 && getTrackTintList() == null) {
            setTrackTintList(getMaterialThemeColorsTrackTintList());
        }
    }

    public void setUseMaterialThemeColors(boolean z) {
        this.j1 = z;
        if (z) {
            setThumbTintList(getMaterialThemeColorsThumbTintList());
            setTrackTintList(getMaterialThemeColorsTrackTintList());
        } else {
            setThumbTintList(null);
            setTrackTintList(null);
        }
    }

    public a(Context context, AttributeSet attributeSet, int i) {
        super(com.google.android.material.theme.overlay.a.a(context, attributeSet, i, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_CompoundButton_Switch), attributeSet, i);
        Context context2 = getContext();
        this.g1 = new com.google.android.material.elevation.a(context2);
        TypedArray typedArrayL = p.l(context2, attributeSet, com.google.android.material.a.N, i, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_CompoundButton_Switch, new int[0]);
        this.j1 = typedArrayL.getBoolean(0, false);
        typedArrayL.recycle();
    }
}
