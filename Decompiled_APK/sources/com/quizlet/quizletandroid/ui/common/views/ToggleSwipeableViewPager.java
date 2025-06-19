package com.quizlet.quizletandroid.ui.common.views;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import androidx.viewpager.widget.ViewPager;

/* loaded from: classes3.dex */
public class ToggleSwipeableViewPager extends ViewPager {
    public boolean m1;

    public ToggleSwipeableViewPager(Context context) {
        super(context);
        this.m1 = true;
    }

    @Override // androidx.viewpager.widget.ViewPager, android.view.ViewGroup
    public final boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        if (this.m1) {
            return super.onInterceptTouchEvent(motionEvent);
        }
        return false;
    }

    @Override // androidx.viewpager.widget.ViewPager, android.view.View
    public final boolean onTouchEvent(MotionEvent motionEvent) {
        if (this.m1) {
            return super.onTouchEvent(motionEvent);
        }
        return false;
    }

    public void setSwipeable(boolean z) {
        this.m1 = z;
    }

    public ToggleSwipeableViewPager(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.m1 = true;
    }
}
