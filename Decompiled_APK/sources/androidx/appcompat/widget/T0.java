package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.Configuration;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.DecelerateInterpolator;
import android.widget.AdapterView;
import android.widget.HorizontalScrollView;
import android.widget.SpinnerAdapter;
import androidx.annotation.NonNull;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public class T0 extends HorizontalScrollView implements AdapterView.OnItemSelectedListener {
    public RunnableC0091j a;
    public final LinearLayoutCompat b;
    public AppCompatSpinner c;
    public boolean d;
    public int e;
    public int f;
    public int g;
    public int h;

    static {
        new DecelerateInterpolator();
    }

    public T0(@NonNull Context context) {
        super(context);
        new S0(this, 0);
        setHorizontalScrollBarEnabled(false);
        androidx.appcompat.view.a aVarA = androidx.appcompat.view.a.a(context);
        setContentHeight(aVarA.e());
        this.f = aVarA.a.getResources().getDimensionPixelSize(R.dimen.abc_action_bar_stacked_tab_max_width);
        LinearLayoutCompat linearLayoutCompat = new LinearLayoutCompat(getContext(), null, R.attr.actionBarTabBarStyle);
        linearLayoutCompat.setMeasureWithLargestChildEnabled(true);
        linearLayoutCompat.setGravity(17);
        linearLayoutCompat.setLayoutParams(new C0121y0(-2, -1));
        this.b = linearLayoutCompat;
        addView(linearLayoutCompat, new ViewGroup.LayoutParams(-2, -1));
    }

    public final void a() {
        AppCompatSpinner appCompatSpinner = this.c;
        if (appCompatSpinner != null && appCompatSpinner.getParent() == this) {
            removeView(this.c);
            addView(this.b, new ViewGroup.LayoutParams(-2, -1));
            setTabSelected(this.c.getSelectedItemPosition());
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        RunnableC0091j runnableC0091j = this.a;
        if (runnableC0091j != null) {
            post(runnableC0091j);
        }
    }

    @Override // android.view.View
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        androidx.appcompat.view.a aVarA = androidx.appcompat.view.a.a(getContext());
        setContentHeight(aVarA.e());
        this.f = aVarA.a.getResources().getDimensionPixelSize(R.dimen.abc_action_bar_stacked_tab_max_width);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        RunnableC0091j runnableC0091j = this.a;
        if (runnableC0091j != null) {
            removeCallbacks(runnableC0091j);
        }
    }

    @Override // android.widget.AdapterView.OnItemSelectedListener
    public final void onItemSelected(AdapterView adapterView, View view, int i, long j) {
        ((R0) view).getClass();
        throw null;
    }

    @Override // android.widget.HorizontalScrollView, android.widget.FrameLayout, android.view.View
    public final void onMeasure(int i, int i2) {
        int mode = View.MeasureSpec.getMode(i);
        boolean z = mode == 1073741824;
        setFillViewport(z);
        LinearLayoutCompat linearLayoutCompat = this.b;
        int childCount = linearLayoutCompat.getChildCount();
        if (childCount <= 1 || !(mode == 1073741824 || mode == Integer.MIN_VALUE)) {
            this.e = -1;
        } else {
            if (childCount > 2) {
                this.e = (int) (View.MeasureSpec.getSize(i) * 0.4f);
            } else {
                this.e = View.MeasureSpec.getSize(i) / 2;
            }
            this.e = Math.min(this.e, this.f);
        }
        int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(this.g, 1073741824);
        if (z || !this.d) {
            a();
        } else {
            linearLayoutCompat.measure(0, iMakeMeasureSpec);
            if (linearLayoutCompat.getMeasuredWidth() > View.MeasureSpec.getSize(i)) {
                AppCompatSpinner appCompatSpinner = this.c;
                if (appCompatSpinner == null || appCompatSpinner.getParent() != this) {
                    if (this.c == null) {
                        AppCompatSpinner appCompatSpinner2 = new AppCompatSpinner(getContext(), null, R.attr.actionDropDownStyle);
                        appCompatSpinner2.setLayoutParams(new C0121y0(-2, -1));
                        appCompatSpinner2.setOnItemSelectedListener(this);
                        this.c = appCompatSpinner2;
                    }
                    removeView(linearLayoutCompat);
                    addView(this.c, new ViewGroup.LayoutParams(-2, -1));
                    if (this.c.getAdapter() == null) {
                        this.c.setAdapter((SpinnerAdapter) new Q0(this));
                    }
                    Runnable runnable = this.a;
                    if (runnable != null) {
                        removeCallbacks(runnable);
                        this.a = null;
                    }
                    this.c.setSelection(this.h);
                }
            } else {
                a();
            }
        }
        int measuredWidth = getMeasuredWidth();
        super.onMeasure(i, iMakeMeasureSpec);
        int measuredWidth2 = getMeasuredWidth();
        if (!z || measuredWidth == measuredWidth2) {
            return;
        }
        setTabSelected(this.h);
    }

    @Override // android.widget.AdapterView.OnItemSelectedListener
    public final void onNothingSelected(AdapterView adapterView) {
    }

    public void setAllowCollapse(boolean z) {
        this.d = z;
    }

    public void setContentHeight(int i) {
        this.g = i;
        requestLayout();
    }

    public void setTabSelected(int i) {
        this.h = i;
        LinearLayoutCompat linearLayoutCompat = this.b;
        int childCount = linearLayoutCompat.getChildCount();
        int i2 = 0;
        while (i2 < childCount) {
            View childAt = linearLayoutCompat.getChildAt(i2);
            boolean z = i2 == i;
            childAt.setSelected(z);
            if (z) {
                View childAt2 = linearLayoutCompat.getChildAt(i);
                Runnable runnable = this.a;
                if (runnable != null) {
                    removeCallbacks(runnable);
                }
                RunnableC0091j runnableC0091j = new RunnableC0091j(1, this, childAt2);
                this.a = runnableC0091j;
                post(runnableC0091j);
            }
            i2++;
        }
        AppCompatSpinner appCompatSpinner = this.c;
        if (appCompatSpinner == null || i < 0) {
            return;
        }
        appCompatSpinner.setSelection(i);
    }
}
