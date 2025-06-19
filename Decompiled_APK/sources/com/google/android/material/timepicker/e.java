package com.google.android.material.timepicker;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.os.Handler;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.compose.ui.text.input.C;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.k;
import androidx.constraintlayout.widget.o;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G4;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class e extends ConstraintLayout {
    public final C q;
    public int r;
    public final com.google.android.material.shape.g s;

    public e(@NonNull Context context) {
        this(context, null, 0);
    }

    @Override // android.view.ViewGroup
    public final void addView(View view, int i, ViewGroup.LayoutParams layoutParams) {
        super.addView(view, i, layoutParams);
        if (view.getId() == -1) {
            WeakHashMap weakHashMap = V.a;
            view.setId(View.generateViewId());
        }
        Handler handler = getHandler();
        if (handler != null) {
            C c = this.q;
            handler.removeCallbacks(c);
            handler.post(c);
        }
    }

    @Override // android.view.View
    public final void onFinishInflate() {
        super.onFinishInflate();
        p();
    }

    @Override // androidx.constraintlayout.widget.ConstraintLayout, android.view.ViewGroup
    public final void onViewRemoved(View view) {
        super.onViewRemoved(view);
        Handler handler = getHandler();
        if (handler != null) {
            C c = this.q;
            handler.removeCallbacks(c);
            handler.post(c);
        }
    }

    public void p() {
        o oVar = new o();
        oVar.d(this);
        HashMap map = new HashMap();
        for (int i = 0; i < getChildCount(); i++) {
            View childAt = getChildAt(i);
            if (childAt.getId() != R.id.circle_center && !"skip".equals(childAt.getTag())) {
                int i2 = (Integer) childAt.getTag(R.id.material_clock_level);
                if (i2 == null) {
                    i2 = 1;
                }
                if (!map.containsKey(i2)) {
                    map.put(i2, new ArrayList());
                }
                ((List) map.get(i2)).add(childAt);
            }
        }
        for (Map.Entry entry : map.entrySet()) {
            List list = (List) entry.getValue();
            int iRound = ((Integer) entry.getKey()).intValue() == 2 ? Math.round(this.r * 0.66f) : this.r;
            Iterator it2 = list.iterator();
            float size = DefinitionKt.NO_Float_VALUE;
            while (it2.hasNext()) {
                k kVar = oVar.h(((View) it2.next()).getId()).d;
                kVar.A = R.id.circle_center;
                kVar.B = iRound;
                kVar.C = size;
                size += 360.0f / list.size();
            }
        }
        oVar.a(this);
    }

    @Override // android.view.View
    public final void setBackgroundColor(int i) {
        this.s.m(ColorStateList.valueOf(i));
    }

    public e(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        LayoutInflater.from(context).inflate(R.layout.material_radial_view_group, this);
        com.google.android.material.shape.g gVar = new com.google.android.material.shape.g();
        this.s = gVar;
        com.google.android.material.shape.h hVar = new com.google.android.material.shape.h(0.5f);
        G4 g4F = gVar.a.a.f();
        g4F.e = hVar;
        g4F.f = hVar;
        g4F.g = hVar;
        g4F.h = hVar;
        gVar.setShapeAppearanceModel(g4F.a());
        this.s.m(ColorStateList.valueOf(-1));
        com.google.android.material.shape.g gVar2 = this.s;
        WeakHashMap weakHashMap = V.a;
        setBackground(gVar2);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.google.android.material.a.G, i, 0);
        this.r = typedArrayObtainStyledAttributes.getDimensionPixelSize(0, 0);
        this.q = new C(this, 28);
        typedArrayObtainStyledAttributes.recycle();
    }
}
