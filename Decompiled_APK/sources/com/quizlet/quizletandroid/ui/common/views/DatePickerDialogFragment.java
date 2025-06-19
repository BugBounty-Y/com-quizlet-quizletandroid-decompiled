package com.quizlet.quizletandroid.ui.common.views;

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.TextUtils;
import android.widget.DatePicker;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.widgets.EditTextDatePicker;
import java.util.Calendar;

/* loaded from: classes3.dex */
public class DatePickerDialogFragment extends DialogInterfaceOnCancelListenerC1151t {
    public EditTextDatePicker q;
    public boolean r = false;
    public EditTextDatePicker s;

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Bundle arguments = getArguments();
        int i = arguments.getInt("Year");
        int i2 = arguments.getInt("Month");
        int i3 = arguments.getInt("Day");
        String string = arguments.getString("Message");
        int i4 = arguments.getInt("Range");
        final d dVar = new d(getContext(), this.r ? R.style.QuizletCalendarDatePickerDialogTheme : R.style.QuizletSpinnerDatePickerDialogTheme, null, i, i2, i3);
        if (!TextUtils.isEmpty(string)) {
            dVar.setMessage(string);
        }
        dVar.setButton(-1, getString(android.R.string.ok), new DialogInterface.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.common.views.b
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i5) {
                DatePickerDialogFragment datePickerDialogFragment = this.a;
                datePickerDialogFragment.getClass();
                DatePicker datePicker = dVar.getDatePicker();
                EditTextDatePicker editTextDatePicker = datePickerDialogFragment.s;
                if (editTextDatePicker != null) {
                    editTextDatePicker.onDateSet(datePicker, datePicker.getYear(), datePicker.getMonth(), datePicker.getDayOfMonth());
                }
                datePickerDialogFragment.H(false, false);
            }
        });
        dVar.setButton(-2, getString(android.R.string.cancel), new com.quizlet.explanations.questiondetail.ui.d(this, 2));
        DatePicker datePicker = dVar.getDatePicker();
        if (i4 == 1) {
            Calendar calendar = Calendar.getInstance();
            calendar.set(10, 23);
            calendar.set(12, 59);
            calendar.set(13, 59);
            datePicker.setMaxDate(calendar.getTimeInMillis());
            return dVar;
        }
        if (i4 == 2) {
            Calendar calendar2 = Calendar.getInstance();
            calendar2.add(5, -1);
            calendar2.set(10, 23);
            calendar2.set(12, 59);
            calendar2.set(13, 59);
            datePicker.setMaxDate(calendar2.getTimeInMillis());
            return dVar;
        }
        if (i4 == 3) {
            Calendar calendar3 = Calendar.getInstance();
            calendar3.set(10, 0);
            calendar3.set(12, 0);
            calendar3.set(13, 0);
            datePicker.setMinDate(calendar3.getTimeInMillis());
            return dVar;
        }
        if (i4 != 4) {
            return dVar;
        }
        Calendar calendar4 = Calendar.getInstance();
        calendar4.add(5, 1);
        calendar4.set(10, 0);
        calendar4.set(12, 0);
        calendar4.set(13, 0);
        datePicker.setMinDate(calendar4.getTimeInMillis());
        return dVar;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (bundle != null) {
            this.r = bundle.getBoolean("shouldUseCalendarMode");
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDetach() {
        this.s = null;
        super.onDetach();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialogInterface) {
        EditTextDatePicker editTextDatePicker = this.q;
        if (editTextDatePicker != null) {
            editTextDatePicker.clearFocus();
        }
        super.onDismiss(dialogInterface);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        bundle.putBoolean("shouldUseCalendarMode", this.r);
    }
}
