package com.quizlet.quizletandroid.ui.common.widgets;

import android.app.DatePickerDialog;
import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.View;
import android.widget.DatePicker;
import android.widget.LinearLayout;
import androidx.lifecycle.p0;
import com.quizlet.quizletandroid.ui.login.BaseSignupFragment;
import com.quizlet.quizletandroid.ui.login.viewmodels.i;
import com.quizlet.quizletandroid.ui.login.viewmodels.j;
import com.quizlet.quizletandroid.v;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public class EditTextDatePicker extends e implements DatePickerDialog.OnDateSetListener {
    public int A;
    public com.quizlet.time.c B;
    public int C;
    public a D;
    public c E;
    public DateFormat F;
    public final com.quizlet.time.b z;

    public EditTextDatePicker(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        if (!isInEditMode() && !this.y) {
            this.y = true;
            ((v) ((d) d())).getClass();
            this.z = com.quizlet.time.b.a;
        }
        this.D = null;
        this.E = null;
        if (isInEditMode()) {
            return;
        }
        setSaveEnabled(true);
        this.F = android.text.format.DateFormat.getMediumDateFormat(context);
        setInputType(0);
        setLongClickable(false);
        this.z.getClass();
        Calendar calendarB = com.quizlet.time.b.b();
        int i = calendarB.get(1);
        com.quizlet.time.c cVar = new com.quizlet.time.c(calendarB.get(2));
        int i2 = calendarB.get(5);
        this.A = i;
        this.B = cVar;
        this.C = i2;
        l();
        DateFormat dateFormat = this.F;
        this.z.getClass();
        setHint(dateFormat.format(com.quizlet.time.b.b().getTime()));
        getEditText().setText("");
    }

    private int getMonthInteger() {
        return this.B.a;
    }

    public DateFormat getDateFormat() {
        return this.F;
    }

    public int getDay() {
        return this.C;
    }

    public com.quizlet.time.c getMonth() {
        return this.B;
    }

    public a getOnDateSetListener() {
        return this.D;
    }

    public int getYear() {
        return this.A;
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.QFormField
    public final void j(boolean z) {
        c cVar;
        super.j(z);
        if (!z || (cVar = this.E) == null) {
            return;
        }
        j jVar = (j) cVar;
        E.A(p0.j(jVar), null, null, new i(jVar, null), 3);
    }

    public final void l() {
        getEditText().setText(this.F.format(new GregorianCalendar(getYear(), getMonthInteger(), getDay()).getTime()));
    }

    @Override // android.app.DatePickerDialog.OnDateSetListener
    public final void onDateSet(DatePicker datePicker, int i, int i2, int i3) {
        com.quizlet.time.c cVar = new com.quizlet.time.c(i2);
        this.A = i;
        this.B = cVar;
        this.C = i3;
        l();
        datePicker.clearFocus();
        clearFocus();
        a aVar = this.D;
        if (aVar != null) {
            com.quizlet.time.c month = getMonth();
            BaseSignupFragment baseSignupFragment = (BaseSignupFragment) ((com.quizlet.infra.legacysyncengine.tasks.parse.b) aVar).b;
            baseSignupFragment.W();
            Context context = baseSignupFragment.getContext();
            if (context != null) {
                Intrinsics.d(month);
                QFormField qFormFieldR = baseSignupFragment.R();
                LinearLayout linearLayout = (LinearLayout) baseSignupFragment.T().b;
                Intrinsics.checkNotNullExpressionValue(linearLayout, "getRoot(...)");
                baseSignupFragment.V(context, i, month, i3, qFormFieldR, linearLayout);
            }
        }
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.QFormField, android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.a);
        this.A = savedState.b;
        this.B = new com.quizlet.time.c(savedState.c);
        this.C = savedState.d;
        for (int i = 0; i < getChildCount(); i++) {
            getChildAt(i).restoreHierarchyState(savedState.e);
        }
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.QFormField, android.view.View
    public final Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState((QFormField.SavedState) super.onSaveInstanceState(), getYear(), getMonthInteger(), getDay());
        for (int i = 0; i < getChildCount(); i++) {
            getChildAt(i).saveHierarchyState(savedState.e);
        }
        return savedState;
    }

    public void setDateFormat(DateFormat dateFormat) {
        this.F = dateFormat;
        l();
    }

    public void setDay(int i) {
        this.C = i;
        l();
    }

    public void setMonth(com.quizlet.time.c cVar) {
        this.B = cVar;
        l();
    }

    public void setOnDateSetListener(a aVar) {
        this.D = aVar;
    }

    public void setShowDatePickerListener(c cVar) {
        this.E = cVar;
    }

    public void setYear(int i) {
        this.A = i;
        l();
    }

    public static class SavedState extends View.BaseSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new b();
        public final Parcelable a;
        public final int b;
        public final int c;
        public final int d;
        public final SparseArray e;

        public SavedState(Parcel parcel) {
            super(parcel);
            this.a = parcel.readParcelable(QFormField.class.getClassLoader());
            this.b = parcel.readInt();
            this.c = parcel.readInt();
            this.d = parcel.readInt();
            this.e = parcel.readSparseArray(getClass().getClassLoader());
        }

        @Override // android.view.View.BaseSavedState, android.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeParcelable(this.a, i);
            parcel.writeInt(this.b);
            parcel.writeInt(this.c);
            parcel.writeInt(this.d);
            parcel.writeSparseArray(this.e);
        }

        public SavedState(QFormField.SavedState savedState, int i, int i2, int i3) {
            super(View.BaseSavedState.EMPTY_STATE);
            this.a = savedState;
            this.b = i;
            this.c = i2;
            this.d = i3;
            this.e = new SparseArray();
        }
    }

    public EditTextDatePicker(Context context) {
        this(context, null);
    }
}
