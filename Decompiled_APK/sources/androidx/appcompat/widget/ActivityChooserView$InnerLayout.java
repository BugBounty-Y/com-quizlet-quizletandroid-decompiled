package androidx.appcompat.widget;

import android.R;
import android.content.Context;
import android.util.AttributeSet;
import android.widget.LinearLayout;

/* loaded from: classes.dex */
public class ActivityChooserView$InnerLayout extends LinearLayout {
    public static final int[] a = {R.attr.background};

    public ActivityChooserView$InnerLayout(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        com.quizlet.data.repository.classfolder.e eVarL = com.quizlet.data.repository.classfolder.e.l(context, attributeSet, a);
        setBackgroundDrawable(eVarL.f(0));
        eVarL.n();
    }
}
