package com.google.android.material.datepicker;

import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import java.util.Calendar;

/* loaded from: classes2.dex */
public final class f implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ r b;
    public final /* synthetic */ k c;

    public /* synthetic */ f(k kVar, r rVar, int i) {
        this.a = i;
        this.c = kVar;
        this.b = rVar;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        switch (this.a) {
            case 0:
                k kVar = this.c;
                int iU0 = ((LinearLayoutManager) kVar.h.getLayoutManager()).U0() - 1;
                if (iU0 >= 0) {
                    Calendar calendarA = v.a(this.b.a.a.a);
                    calendarA.add(2, iU0);
                    kVar.G(new Month(calendarA));
                    break;
                }
                break;
            default:
                k kVar2 = this.c;
                int iS0 = ((LinearLayoutManager) kVar2.h.getLayoutManager()).S0() + 1;
                if (iS0 < kVar2.h.getAdapter().getItemCount()) {
                    Calendar calendarA2 = v.a(this.b.a.a.a);
                    calendarA2.add(2, iS0);
                    kVar2.G(new Month(calendarA2));
                    break;
                }
                break;
        }
    }
}
