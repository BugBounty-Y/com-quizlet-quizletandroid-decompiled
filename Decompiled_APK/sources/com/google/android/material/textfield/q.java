package com.google.android.material.textfield;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.RippleDrawable;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;
import androidx.core.view.V;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class q extends ArrayAdapter {
    public ColorStateList a;
    public ColorStateList b;
    public final /* synthetic */ r c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(r rVar, Context context, int i, String[] strArr) {
        super(context, i, strArr);
        this.c = rVar;
        a();
    }

    public final void a() {
        ColorStateList colorStateList;
        r rVar = this.c;
        ColorStateList colorStateList2 = rVar.l;
        ColorStateList colorStateList3 = null;
        if (colorStateList2 != null) {
            int[] iArr = {R.attr.state_pressed};
            colorStateList = new ColorStateList(new int[][]{iArr, new int[0]}, new int[]{colorStateList2.getColorForState(iArr, 0), 0});
        } else {
            colorStateList = null;
        }
        this.b = colorStateList;
        if (rVar.k != 0 && rVar.l != null) {
            int[] iArr2 = {R.attr.state_hovered, -16842919};
            int[] iArr3 = {R.attr.state_selected, -16842919};
            colorStateList3 = new ColorStateList(new int[][]{iArr3, iArr2, new int[0]}, new int[]{androidx.core.graphics.d.b(rVar.l.getColorForState(iArr3, 0), rVar.k), androidx.core.graphics.d.b(rVar.l.getColorForState(iArr2, 0), rVar.k), rVar.k});
        }
        this.a = colorStateList3;
    }

    @Override // android.widget.ArrayAdapter, android.widget.Adapter
    public final View getView(int i, View view, ViewGroup viewGroup) {
        View view2 = super.getView(i, view, viewGroup);
        if (view2 instanceof TextView) {
            TextView textView = (TextView) view2;
            r rVar = this.c;
            Drawable rippleDrawable = null;
            if (rVar.getText().toString().contentEquals(textView.getText()) && rVar.k != 0) {
                ColorDrawable colorDrawable = new ColorDrawable(rVar.k);
                if (this.b != null) {
                    colorDrawable.setTintList(this.a);
                    rippleDrawable = new RippleDrawable(this.b, colorDrawable, null);
                } else {
                    rippleDrawable = colorDrawable;
                }
            }
            WeakHashMap weakHashMap = V.a;
            textView.setBackground(rippleDrawable);
        }
        return view2;
    }
}
