package com.google.android.material.datepicker;

import android.R;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.ContextThemeWrapper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.GridView;
import android.widget.ListAdapter;
import androidx.appcompat.app.ViewOnClickListenerC0045a;
import androidx.core.view.V;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.T;
import com.google.android.material.button.MaterialButton;

/* loaded from: classes2.dex */
public final class k<S> extends s {
    public int b;
    public CalendarConstraints c;
    public Month d;
    public int e;
    public d f;
    public RecyclerView g;
    public RecyclerView h;
    public View i;
    public View j;
    public View k;
    public View l;

    public final void G(Month month) {
        r rVar = (r) this.h.getAdapter();
        int iD = rVar.a.a.d(month);
        int iD2 = iD - rVar.a.a.d(this.d);
        boolean z = Math.abs(iD2) > 3;
        boolean z2 = iD2 > 0;
        this.d = month;
        if (z && z2) {
            this.h.k0(iD - 3);
            this.h.post(new androidx.core.provider.a(this, iD, 9));
        } else if (!z) {
            this.h.post(new androidx.core.provider.a(this, iD, 9));
        } else {
            this.h.k0(iD + 3);
            this.h.post(new androidx.core.provider.a(this, iD, 9));
        }
    }

    public final void H(int i) {
        this.e = i;
        if (i == 2) {
            this.g.getLayoutManager().v0(this.d.c - ((x) this.g.getAdapter()).a.c.a.c);
            this.k.setVisibility(0);
            this.l.setVisibility(8);
            this.i.setVisibility(8);
            this.j.setVisibility(8);
            return;
        }
        if (i == 1) {
            this.k.setVisibility(8);
            this.l.setVisibility(0);
            this.i.setVisibility(0);
            this.j.setVisibility(0);
            G(this.d);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (bundle == null) {
            bundle = getArguments();
        }
        this.b = bundle.getInt("THEME_RES_ID_KEY");
        if (bundle.getParcelable("GRID_SELECTOR_KEY") != null) {
            throw new ClassCastException();
        }
        this.c = (CalendarConstraints) bundle.getParcelable("CALENDAR_CONSTRAINTS_KEY");
        if (bundle.getParcelable("DAY_VIEW_DECORATOR_KEY") != null) {
            throw new ClassCastException();
        }
        this.d = (Month) bundle.getParcelable("CURRENT_MONTH_KEY");
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) throws Resources.NotFoundException {
        int i;
        int i2;
        ContextThemeWrapper contextThemeWrapper = new ContextThemeWrapper(getContext(), this.b);
        this.f = new d(contextThemeWrapper);
        LayoutInflater layoutInflaterCloneInContext = layoutInflater.cloneInContext(contextThemeWrapper);
        Month month = this.c.a;
        if (l.R(contextThemeWrapper, R.attr.windowFullscreen)) {
            i = com.quizlet.quizletandroid.R.layout.mtrl_calendar_vertical;
            i2 = 1;
        } else {
            i = com.quizlet.quizletandroid.R.layout.mtrl_calendar_horizontal;
            i2 = 0;
        }
        View viewInflate = layoutInflaterCloneInContext.inflate(i, viewGroup, false);
        Resources resources = requireContext().getResources();
        int dimensionPixelOffset = resources.getDimensionPixelOffset(com.quizlet.quizletandroid.R.dimen.mtrl_calendar_navigation_bottom_padding) + resources.getDimensionPixelOffset(com.quizlet.quizletandroid.R.dimen.mtrl_calendar_navigation_top_padding) + resources.getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.mtrl_calendar_navigation_height);
        int dimensionPixelSize = resources.getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.mtrl_calendar_days_of_week_height);
        int i3 = o.d;
        viewInflate.setMinimumHeight(dimensionPixelOffset + dimensionPixelSize + (resources.getDimensionPixelOffset(com.quizlet.quizletandroid.R.dimen.mtrl_calendar_month_vertical_padding) * (i3 - 1)) + (resources.getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.mtrl_calendar_day_height) * i3) + resources.getDimensionPixelOffset(com.quizlet.quizletandroid.R.dimen.mtrl_calendar_bottom_padding));
        GridView gridView = (GridView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.mtrl_calendar_days_of_week);
        V.o(gridView, new androidx.core.widget.g(1));
        int i4 = this.c.e;
        gridView.setAdapter((ListAdapter) (i4 > 0 ? new e(i4) : new e()));
        gridView.setNumColumns(month.d);
        gridView.setEnabled(false);
        this.h = (RecyclerView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.mtrl_calendar_months);
        getContext();
        this.h.setLayoutManager(new g(this, i2, i2));
        this.h.setTag("MONTHS_VIEW_GROUP_TAG");
        r rVar = new r(contextThemeWrapper, this.c, new h(this));
        this.h.setAdapter(rVar);
        int integer = contextThemeWrapper.getResources().getInteger(com.quizlet.quizletandroid.R.integer.mtrl_calendar_year_selector_span);
        RecyclerView recyclerView = (RecyclerView) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.mtrl_calendar_year_selector_frame);
        this.g = recyclerView;
        if (recyclerView != null) {
            recyclerView.setHasFixedSize(true);
            this.g.setLayoutManager(new GridLayoutManager(integer));
            this.g.setAdapter(new x(this));
            this.g.i(new i(this));
        }
        if (viewInflate.findViewById(com.quizlet.quizletandroid.R.id.month_navigation_fragment_toggle) != null) {
            MaterialButton materialButton = (MaterialButton) viewInflate.findViewById(com.quizlet.quizletandroid.R.id.month_navigation_fragment_toggle);
            materialButton.setTag("SELECTOR_TOGGLE_TAG");
            V.o(materialButton, new androidx.viewpager.widget.e(this, 3));
            View viewFindViewById = viewInflate.findViewById(com.quizlet.quizletandroid.R.id.month_navigation_previous);
            this.i = viewFindViewById;
            viewFindViewById.setTag("NAVIGATION_PREV_TAG");
            View viewFindViewById2 = viewInflate.findViewById(com.quizlet.quizletandroid.R.id.month_navigation_next);
            this.j = viewFindViewById2;
            viewFindViewById2.setTag("NAVIGATION_NEXT_TAG");
            this.k = viewInflate.findViewById(com.quizlet.quizletandroid.R.id.mtrl_calendar_year_selector_frame);
            this.l = viewInflate.findViewById(com.quizlet.quizletandroid.R.id.mtrl_calendar_day_selector_frame);
            H(1);
            materialButton.setText(this.d.c());
            this.h.k(new j(this, rVar, materialButton));
            materialButton.setOnClickListener(new ViewOnClickListenerC0045a(this, 6));
            this.j.setOnClickListener(new f(this, rVar, 1));
            this.i.setOnClickListener(new f(this, rVar, 0));
        }
        if (!l.R(contextThemeWrapper, R.attr.windowFullscreen)) {
            new T(1).a(this.h);
        }
        this.h.k0(rVar.a.a.d(this.d));
        V.o(this.h, new androidx.core.widget.g(2));
        return viewInflate;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle bundle) {
        bundle.putInt("THEME_RES_ID_KEY", this.b);
        bundle.putParcelable("GRID_SELECTOR_KEY", null);
        bundle.putParcelable("CALENDAR_CONSTRAINTS_KEY", this.c);
        bundle.putParcelable("DAY_VIEW_DECORATOR_KEY", null);
        bundle.putParcelable("CURRENT_MONTH_KEY", this.d);
    }
}
