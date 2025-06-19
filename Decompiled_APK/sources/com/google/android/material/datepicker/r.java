package com.google.android.material.datepicker;

import android.view.ContextThemeWrapper;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.C1383o0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import java.util.Calendar;

/* loaded from: classes2.dex */
public final class r extends AbstractC1361d0 {
    public final CalendarConstraints a;
    public final h b;
    public final int c;

    public r(ContextThemeWrapper contextThemeWrapper, CalendarConstraints calendarConstraints, h hVar) {
        Month month = calendarConstraints.a;
        Month month2 = calendarConstraints.d;
        if (month.a.compareTo(month2.a) > 0) {
            throw new IllegalArgumentException("firstPage cannot be after currentPage");
        }
        if (month2.a.compareTo(calendarConstraints.b.a) > 0) {
            throw new IllegalArgumentException("currentPage cannot be after lastPage");
        }
        this.c = (contextThemeWrapper.getResources().getDimensionPixelSize(R.dimen.mtrl_calendar_day_height) * o.d) + (l.R(contextThemeWrapper, android.R.attr.windowFullscreen) ? contextThemeWrapper.getResources().getDimensionPixelSize(R.dimen.mtrl_calendar_day_height) : 0);
        this.a = calendarConstraints;
        this.b = hVar;
        setHasStableIds(true);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.a.g;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final long getItemId(int i) {
        Calendar calendarA = v.a(this.a.a.a);
        calendarA.add(2, i);
        return new Month(calendarA).a.getTimeInMillis();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        q qVar = (q) f0;
        CalendarConstraints calendarConstraints = this.a;
        Calendar calendarA = v.a(calendarConstraints.a.a);
        calendarA.add(2, i);
        Month month = new Month(calendarA);
        qVar.a.setText(month.c());
        MaterialCalendarGridView materialCalendarGridView = (MaterialCalendarGridView) qVar.b.findViewById(R.id.month_grid);
        if (materialCalendarGridView.a() == null || !month.equals(materialCalendarGridView.a().a)) {
            new o(month, calendarConstraints);
            throw null;
        }
        materialCalendarGridView.invalidate();
        materialCalendarGridView.a().getClass();
        throw null;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        LinearLayout linearLayout = (LinearLayout) Z.c(viewGroup, R.layout.mtrl_calendar_month_labeled, viewGroup, false);
        if (!l.R(viewGroup.getContext(), android.R.attr.windowFullscreen)) {
            return new q(linearLayout, false);
        }
        linearLayout.setLayoutParams(new C1383o0(-1, this.c));
        return new q(linearLayout, true);
    }
}
