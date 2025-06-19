package com.google.android.material.datepicker;

import android.widget.BaseAdapter;
import java.util.Calendar;

/* loaded from: classes2.dex */
public final class o extends BaseAdapter {
    public static final int d = v.c(null).getMaximum(4);
    public static final int e = (v.c(null).getMaximum(7) + v.c(null).getMaximum(5)) - 1;
    public final Month a;
    public d b;
    public final CalendarConstraints c;

    public o(Month month, CalendarConstraints calendarConstraints) {
        this.a = month;
        this.c = calendarConstraints;
        throw null;
    }

    public final int a() {
        int firstDayOfWeek = this.c.e;
        Month month = this.a;
        Calendar calendar = month.a;
        int i = calendar.get(7);
        if (firstDayOfWeek <= 0) {
            firstDayOfWeek = calendar.getFirstDayOfWeek();
        }
        int i2 = i - firstDayOfWeek;
        return i2 < 0 ? i2 + month.d : i2;
    }

    @Override // android.widget.Adapter
    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    public final Long getItem(int i) {
        if (i < a() || i > c()) {
            return null;
        }
        int iA = (i - a()) + 1;
        Calendar calendarA = v.a(this.a.a);
        calendarA.set(5, iA);
        return Long.valueOf(calendarA.getTimeInMillis());
    }

    public final int c() {
        return (a() + this.a.e) - 1;
    }

    @Override // android.widget.Adapter
    public final int getCount() {
        return e;
    }

    @Override // android.widget.Adapter
    public final long getItemId(int i) {
        return i / this.a.d;
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0055  */
    @Override // android.widget.Adapter
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View getView(int r5, android.view.View r6, android.view.ViewGroup r7) {
        /*
            r4 = this;
            android.content.Context r0 = r7.getContext()
            com.google.android.material.datepicker.d r1 = r4.b
            if (r1 != 0) goto Lf
            com.google.android.material.datepicker.d r1 = new com.google.android.material.datepicker.d
            r1.<init>(r0)
            r4.b = r1
        Lf:
            r0 = r6
            android.widget.TextView r0 = (android.widget.TextView) r0
            r1 = 0
            if (r6 != 0) goto L1f
            r6 = 2131624886(0x7f0e03b6, float:1.8876964E38)
            android.view.View r6 = com.google.android.gms.measurement.internal.Z.c(r7, r6, r7, r1)
            r0 = r6
            android.widget.TextView r0 = (android.widget.TextView) r0
        L1f:
            int r6 = r4.a()
            int r6 = r5 - r6
            if (r6 < 0) goto L55
            com.google.android.material.datepicker.Month r7 = r4.a
            int r2 = r7.e
            if (r6 < r2) goto L2e
            goto L55
        L2e:
            r2 = 1
            int r6 = r6 + r2
            r0.setTag(r7)
            android.content.res.Resources r7 = r0.getResources()
            android.content.res.Configuration r7 = r7.getConfiguration()
            java.util.Locale r7 = r7.locale
            java.lang.Integer r6 = java.lang.Integer.valueOf(r6)
            java.lang.Object[] r6 = new java.lang.Object[]{r6}
            java.lang.String r3 = "%d"
            java.lang.String r6 = java.lang.String.format(r7, r3, r6)
            r0.setText(r6)
            r0.setVisibility(r1)
            r0.setEnabled(r2)
            goto L5d
        L55:
            r6 = 8
            r0.setVisibility(r6)
            r0.setEnabled(r1)
        L5d:
            java.lang.Long r5 = r4.getItem(r5)
            if (r5 != 0) goto L64
            goto L66
        L64:
            if (r0 != 0) goto L67
        L66:
            return r0
        L67:
            r0.getContext()
            java.util.Calendar r5 = com.google.android.material.datepicker.v.b()
            r5.getTimeInMillis()
            r5 = 0
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.datepicker.o.getView(int, android.view.View, android.view.ViewGroup):android.view.View");
    }

    @Override // android.widget.BaseAdapter, android.widget.Adapter
    public final boolean hasStableIds() {
        return true;
    }
}
