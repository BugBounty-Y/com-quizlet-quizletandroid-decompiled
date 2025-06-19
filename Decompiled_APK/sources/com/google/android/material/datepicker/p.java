package com.google.android.material.datepicker;

import android.view.View;
import android.widget.AdapterView;

/* loaded from: classes2.dex */
public final class p implements AdapterView.OnItemClickListener {
    public final /* synthetic */ MaterialCalendarGridView a;
    public final /* synthetic */ r b;

    public p(r rVar, MaterialCalendarGridView materialCalendarGridView) {
        this.b = rVar;
        this.a = materialCalendarGridView;
    }

    @Override // android.widget.AdapterView.OnItemClickListener
    public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
        MaterialCalendarGridView materialCalendarGridView = this.a;
        o oVarA = materialCalendarGridView.a();
        if (i < oVarA.a() || i > oVarA.c()) {
            return;
        }
        if (materialCalendarGridView.a().getItem(i).longValue() >= ((DateValidatorPointForward) this.b.b.a.c.c).a) {
            throw null;
        }
    }
}
