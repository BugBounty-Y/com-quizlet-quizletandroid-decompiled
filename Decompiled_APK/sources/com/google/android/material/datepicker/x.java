package com.google.android.material.datepicker;

import android.content.Context;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class x extends AbstractC1361d0 {
    public final k a;

    public x(k kVar) {
        this.a = kVar;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.a.c.f;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        w wVar = (w) f0;
        k kVar = this.a;
        int i2 = kVar.c.a.c + i;
        wVar.a.setText(String.format(Locale.getDefault(), "%d", Integer.valueOf(i2)));
        TextView textView = wVar.a;
        Context context = textView.getContext();
        textView.setContentDescription(v.b().get(1) == i2 ? String.format(context.getString(R.string.mtrl_picker_navigate_to_current_year_description), Integer.valueOf(i2)) : String.format(context.getString(R.string.mtrl_picker_navigate_to_year_description), Integer.valueOf(i2)));
        d dVar = kVar.f;
        if (v.b().get(1) == i2) {
            c cVar = dVar.b;
        } else {
            c cVar2 = dVar.a;
        }
        throw null;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        return new w((TextView) Z.c(viewGroup, R.layout.mtrl_calendar_year, viewGroup, false));
    }
}
