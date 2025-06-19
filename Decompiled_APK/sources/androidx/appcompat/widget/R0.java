package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.LinearLayout;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public final class R0 extends LinearLayout {
    public final /* synthetic */ T0 a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public R0(T0 t0, Context context) {
        super(context, null, R.attr.actionBarTabStyle);
        this.a = t0;
        com.quizlet.data.repository.classfolder.e eVarM = com.quizlet.data.repository.classfolder.e.m(context, null, new int[]{android.R.attr.background}, R.attr.actionBarTabStyle);
        if (((TypedArray) eVarM.c).hasValue(0)) {
            setBackgroundDrawable(eVarM.f(0));
        }
        eVarM.n();
        setGravity(8388627);
        throw null;
    }

    @Override // android.view.View
    public final void onInitializeAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        super.onInitializeAccessibilityEvent(accessibilityEvent);
        accessibilityEvent.setClassName("androidx.appcompat.app.ActionBar$Tab");
    }

    @Override // android.view.View
    public final void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setClassName("androidx.appcompat.app.ActionBar$Tab");
    }

    @Override // android.widget.LinearLayout, android.view.View
    public final void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        T0 t0 = this.a;
        if (t0.e > 0) {
            int measuredWidth = getMeasuredWidth();
            int i3 = t0.e;
            if (measuredWidth > i3) {
                super.onMeasure(View.MeasureSpec.makeMeasureSpec(i3, 1073741824), i2);
            }
        }
    }

    @Override // android.view.View
    public final void setSelected(boolean z) {
        boolean z2 = isSelected() != z;
        super.setSelected(z);
        if (z2 && z) {
            sendAccessibilityEvent(4);
        }
    }
}
