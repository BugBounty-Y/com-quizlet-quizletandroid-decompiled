package com.google.android.material.datepicker;

import androidx.recyclerview.widget.AbstractC1390s0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.button.MaterialButton;
import java.util.Calendar;

/* loaded from: classes2.dex */
public final class j extends AbstractC1390s0 {
    public final /* synthetic */ r a;
    public final /* synthetic */ MaterialButton b;
    public final /* synthetic */ k c;

    public j(k kVar, r rVar, MaterialButton materialButton) {
        this.c = kVar;
        this.a = rVar;
        this.b = materialButton;
    }

    @Override // androidx.recyclerview.widget.AbstractC1390s0
    public final void a(RecyclerView recyclerView, int i) {
        if (i == 0) {
            recyclerView.announceForAccessibility(this.b.getText());
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1390s0
    public final void b(RecyclerView recyclerView, int i, int i2) {
        k kVar = this.c;
        int iS0 = i < 0 ? ((LinearLayoutManager) kVar.h.getLayoutManager()).S0() : ((LinearLayoutManager) kVar.h.getLayoutManager()).U0();
        CalendarConstraints calendarConstraints = this.a.a;
        Calendar calendarA = v.a(calendarConstraints.a.a);
        calendarA.add(2, iS0);
        kVar.d = new Month(calendarA);
        Calendar calendarA2 = v.a(calendarConstraints.a.a);
        calendarA2.add(2, iS0);
        this.b.setText(new Month(calendarA2).c());
    }
}
