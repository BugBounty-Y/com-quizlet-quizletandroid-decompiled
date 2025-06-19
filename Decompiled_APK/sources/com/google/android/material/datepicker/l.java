package com.google.android.material.datepicker;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.compose.animation.core.U0;
import androidx.compose.animation.d0;
import androidx.core.view.E0;
import androidx.core.view.F0;
import androidx.core.view.G0;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3275u6;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3436c4;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import com.google.android.material.datepicker.CalendarConstraints;
import com.google.android.material.internal.CheckableImageButton;
import com.quizlet.quizletandroid.R;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class l<S> extends DialogInterfaceOnCancelListenerC1151t {
    public int A;
    public CharSequence B;
    public int C;
    public CharSequence D;
    public int E;
    public CharSequence F;
    public int G;
    public CharSequence H;
    public TextView I;
    public CheckableImageButton J;
    public com.google.android.material.shape.g K;
    public boolean L;
    public CharSequence M;
    public CharSequence V;
    public final LinkedHashSet q;
    public final LinkedHashSet r;
    public int s;
    public s t;
    public CalendarConstraints u;
    public k v;
    public int w;
    public CharSequence x;
    public boolean y;
    public int z;

    public l() {
        new LinkedHashSet();
        new LinkedHashSet();
        this.q = new LinkedHashSet();
        this.r = new LinkedHashSet();
    }

    public static int Q(Context context) throws Resources.NotFoundException {
        Resources resources = context.getResources();
        int dimensionPixelOffset = resources.getDimensionPixelOffset(R.dimen.mtrl_calendar_content_padding);
        Month month = new Month(v.b());
        int dimensionPixelSize = resources.getDimensionPixelSize(R.dimen.mtrl_calendar_day_width);
        int dimensionPixelOffset2 = resources.getDimensionPixelOffset(R.dimen.mtrl_calendar_month_horizontal_padding);
        int i = month.d;
        return d0.c(i, 1, dimensionPixelOffset2, (dimensionPixelSize * i) + (dimensionPixelOffset * 2));
    }

    public static boolean R(Context context, int i) throws Resources.NotFoundException {
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(AbstractC3436c4.d(context, k.class.getCanonicalName(), R.attr.materialCalendarStyle).data, new int[]{i});
        boolean z = typedArrayObtainStyledAttributes.getBoolean(0, false);
        typedArrayObtainStyledAttributes.recycle();
        return z;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Context contextRequireContext = requireContext();
        requireContext();
        int i = this.s;
        if (i == 0) {
            P();
            throw null;
        }
        Dialog dialog = new Dialog(contextRequireContext, i);
        Context context = dialog.getContext();
        this.y = R(context, android.R.attr.windowFullscreen);
        this.K = new com.google.android.material.shape.g(context, null, R.attr.materialCalendarStyle, R.style.Widget_MaterialComponents_MaterialCalendar);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(null, com.google.android.material.a.x, R.attr.materialCalendarStyle, R.style.Widget_MaterialComponents_MaterialCalendar);
        int color = typedArrayObtainStyledAttributes.getColor(1, 0);
        typedArrayObtainStyledAttributes.recycle();
        this.K.k(context);
        this.K.m(ColorStateList.valueOf(color));
        com.google.android.material.shape.g gVar = this.K;
        View decorView = dialog.getWindow().getDecorView();
        WeakHashMap weakHashMap = V.a;
        gVar.l(L.e(decorView));
        return dialog;
    }

    public final void P() {
        if (getArguments().getParcelable("DATE_SELECTOR_KEY") != null) {
            throw new ClassCastException();
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnCancelListener
    public final void onCancel(DialogInterface dialogInterface) {
        Iterator it2 = this.q.iterator();
        while (it2.hasNext()) {
            ((DialogInterface.OnCancelListener) it2.next()).onCancel(dialogInterface);
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) throws Resources.NotFoundException {
        super.onCreate(bundle);
        if (bundle == null) {
            bundle = getArguments();
        }
        this.s = bundle.getInt("OVERRIDE_THEME_RES_ID");
        if (bundle.getParcelable("DATE_SELECTOR_KEY") != null) {
            throw new ClassCastException();
        }
        this.u = (CalendarConstraints) bundle.getParcelable("CALENDAR_CONSTRAINTS_KEY");
        if (bundle.getParcelable("DAY_VIEW_DECORATOR_KEY") != null) {
            throw new ClassCastException();
        }
        this.w = bundle.getInt("TITLE_TEXT_RES_ID_KEY");
        this.x = bundle.getCharSequence("TITLE_TEXT_KEY");
        this.z = bundle.getInt("INPUT_MODE_KEY");
        this.A = bundle.getInt("POSITIVE_BUTTON_TEXT_RES_ID_KEY");
        this.B = bundle.getCharSequence("POSITIVE_BUTTON_TEXT_KEY");
        this.C = bundle.getInt("POSITIVE_BUTTON_CONTENT_DESCRIPTION_RES_ID_KEY");
        this.D = bundle.getCharSequence("POSITIVE_BUTTON_CONTENT_DESCRIPTION_KEY");
        this.E = bundle.getInt("NEGATIVE_BUTTON_TEXT_RES_ID_KEY");
        this.F = bundle.getCharSequence("NEGATIVE_BUTTON_TEXT_KEY");
        this.G = bundle.getInt("NEGATIVE_BUTTON_CONTENT_DESCRIPTION_RES_ID_KEY");
        this.H = bundle.getCharSequence("NEGATIVE_BUTTON_CONTENT_DESCRIPTION_KEY");
        CharSequence text = this.x;
        if (text == null) {
            text = requireContext().getResources().getText(this.w);
        }
        this.M = text;
        if (text != null) {
            CharSequence[] charSequenceArrSplit = TextUtils.split(String.valueOf(text), "\n");
            if (charSequenceArrSplit.length > 1) {
                text = charSequenceArrSplit[0];
            }
        } else {
            text = null;
        }
        this.V = text;
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        View viewInflate = layoutInflater.inflate(this.y ? R.layout.mtrl_picker_fullscreen : R.layout.mtrl_picker_dialog, viewGroup);
        Context context = viewInflate.getContext();
        if (this.y) {
            viewInflate.findViewById(R.id.mtrl_calendar_frame).setLayoutParams(new LinearLayout.LayoutParams(Q(context), -2));
        } else {
            viewInflate.findViewById(R.id.mtrl_calendar_main_pane).setLayoutParams(new LinearLayout.LayoutParams(Q(context), -1));
        }
        TextView textView = (TextView) viewInflate.findViewById(R.id.mtrl_picker_header_selection_text);
        WeakHashMap weakHashMap = V.a;
        textView.setAccessibilityLiveRegion(1);
        this.J = (CheckableImageButton) viewInflate.findViewById(R.id.mtrl_picker_header_toggle);
        this.I = (TextView) viewInflate.findViewById(R.id.mtrl_picker_title_text);
        this.J.setTag("TOGGLE_BUTTON_TAG");
        CheckableImageButton checkableImageButton = this.J;
        StateListDrawable stateListDrawable = new StateListDrawable();
        stateListDrawable.addState(new int[]{android.R.attr.state_checked}, com.facebook.appevents.g.f(context, R.drawable.material_ic_calendar_black_24dp));
        stateListDrawable.addState(new int[0], com.facebook.appevents.g.f(context, R.drawable.material_ic_edit_black_24dp));
        checkableImageButton.setImageDrawable(stateListDrawable);
        this.J.setChecked(this.z != 0);
        V.o(this.J, null);
        CheckableImageButton checkableImageButton2 = this.J;
        this.J.setContentDescription(this.z == 1 ? checkableImageButton2.getContext().getString(R.string.mtrl_picker_toggle_to_calendar_input_mode) : checkableImageButton2.getContext().getString(R.string.mtrl_picker_toggle_to_text_input_mode));
        this.J.setOnClickListener(new com.braze.ui.inappmessage.d(this, 4));
        P();
        throw null;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialogInterface) {
        Iterator it2 = this.r.iterator();
        while (it2.hasNext()) {
            ((DialogInterface.OnDismissListener) it2.next()).onDismiss(dialogInterface);
        }
        ViewGroup viewGroup = (ViewGroup) getView();
        if (viewGroup != null) {
            viewGroup.removeAllViews();
        }
        super.onDismiss(dialogInterface);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        bundle.putInt("OVERRIDE_THEME_RES_ID", this.s);
        bundle.putParcelable("DATE_SELECTOR_KEY", null);
        CalendarConstraints calendarConstraints = this.u;
        b bVar = new b();
        int i = b.b;
        int i2 = b.b;
        long j = calendarConstraints.a.f;
        long j2 = calendarConstraints.b.f;
        bVar.a = Long.valueOf(calendarConstraints.d.f);
        k kVar = this.v;
        Month month = kVar == null ? null : kVar.d;
        if (month != null) {
            bVar.a = Long.valueOf(month.f);
        }
        Bundle bundle2 = new Bundle();
        bundle2.putParcelable("DEEP_COPY_VALIDATOR_KEY", calendarConstraints.c);
        Month monthB = Month.b(j);
        Month monthB2 = Month.b(j2);
        CalendarConstraints.DateValidator dateValidator = (CalendarConstraints.DateValidator) bundle2.getParcelable("DEEP_COPY_VALIDATOR_KEY");
        Long l = bVar.a;
        bundle.putParcelable("CALENDAR_CONSTRAINTS_KEY", new CalendarConstraints(monthB, monthB2, dateValidator, l == null ? null : Month.b(l.longValue()), calendarConstraints.e));
        bundle.putParcelable("DAY_VIEW_DECORATOR_KEY", null);
        bundle.putInt("TITLE_TEXT_RES_ID_KEY", this.w);
        bundle.putCharSequence("TITLE_TEXT_KEY", this.x);
        bundle.putInt("INPUT_MODE_KEY", this.z);
        bundle.putInt("POSITIVE_BUTTON_TEXT_RES_ID_KEY", this.A);
        bundle.putCharSequence("POSITIVE_BUTTON_TEXT_KEY", this.B);
        bundle.putInt("POSITIVE_BUTTON_CONTENT_DESCRIPTION_RES_ID_KEY", this.C);
        bundle.putCharSequence("POSITIVE_BUTTON_CONTENT_DESCRIPTION_KEY", this.D);
        bundle.putInt("NEGATIVE_BUTTON_TEXT_RES_ID_KEY", this.E);
        bundle.putCharSequence("NEGATIVE_BUTTON_TEXT_KEY", this.F);
        bundle.putInt("NEGATIVE_BUTTON_CONTENT_DESCRIPTION_RES_ID_KEY", this.G);
        bundle.putCharSequence("NEGATIVE_BUTTON_CONTENT_DESCRIPTION_KEY", this.H);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStart() throws Resources.NotFoundException {
        super.onStart();
        Window window = L().getWindow();
        if (this.y) {
            window.setLayout(-1, -1);
            window.setBackgroundDrawable(this.K);
            if (!this.L) {
                View viewFindViewById = requireView().findViewById(R.id.fullscreen_header);
                ColorStateList colorStateListJ = Y3.j(viewFindViewById.getBackground());
                Integer numValueOf = colorStateListJ != null ? Integer.valueOf(colorStateListJ.getDefaultColor()) : null;
                int i = Build.VERSION.SDK_INT;
                boolean z = false;
                boolean z2 = numValueOf == null || numValueOf.intValue() == 0;
                int iC = X3.c(window.getContext(), android.R.attr.colorBackground, -16777216);
                if (z2) {
                    numValueOf = Integer.valueOf(iC);
                }
                AbstractC3275u6.b(window, false);
                window.getContext();
                int iD = i < 27 ? androidx.core.graphics.d.d(X3.c(window.getContext(), android.R.attr.navigationBarColor, -16777216), 128) : 0;
                window.setStatusBarColor(0);
                window.setNavigationBarColor(iD);
                boolean z3 = X3.d(0) || X3.d(numValueOf.intValue());
                com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(window.getDecorView());
                (i >= 35 ? new G0(window, aVar) : i >= 30 ? new F0(window, aVar) : new E0(window, aVar)).d(z3);
                boolean zD = X3.d(iC);
                if (X3.d(iD) || (iD == 0 && zD)) {
                    z = true;
                }
                com.quizlet.data.repository.school.membership.a aVar2 = new com.quizlet.data.repository.school.membership.a(window.getDecorView());
                int i2 = Build.VERSION.SDK_INT;
                (i2 >= 35 ? new G0(window, aVar2) : i2 >= 30 ? new F0(window, aVar2) : new E0(window, aVar2)).c(z);
                U0 u0 = new U0(viewFindViewById, viewFindViewById.getLayoutParams().height, viewFindViewById.getPaddingTop());
                WeakHashMap weakHashMap = V.a;
                L.m(viewFindViewById, u0);
                this.L = true;
            }
        } else {
            window.setLayout(-2, -2);
            int dimensionPixelOffset = getResources().getDimensionPixelOffset(R.dimen.mtrl_calendar_dialog_background_inset);
            Rect rect = new Rect(dimensionPixelOffset, dimensionPixelOffset, dimensionPixelOffset, dimensionPixelOffset);
            window.setBackgroundDrawable(new InsetDrawable((Drawable) this.K, dimensionPixelOffset, dimensionPixelOffset, dimensionPixelOffset, dimensionPixelOffset));
            window.getDecorView().setOnTouchListener(new com.google.android.material.dialog.a(L(), rect));
        }
        requireContext();
        int i3 = this.s;
        if (i3 == 0) {
            P();
            throw null;
        }
        P();
        CalendarConstraints calendarConstraints = this.u;
        k kVar = new k();
        Bundle bundle = new Bundle();
        bundle.putInt("THEME_RES_ID_KEY", i3);
        bundle.putParcelable("GRID_SELECTOR_KEY", null);
        bundle.putParcelable("CALENDAR_CONSTRAINTS_KEY", calendarConstraints);
        bundle.putParcelable("DAY_VIEW_DECORATOR_KEY", null);
        bundle.putParcelable("CURRENT_MONTH_KEY", calendarConstraints.d);
        kVar.setArguments(bundle);
        this.v = kVar;
        s sVar = kVar;
        if (this.z == 1) {
            P();
            CalendarConstraints calendarConstraints2 = this.u;
            s mVar = new m();
            Bundle bundle2 = new Bundle();
            bundle2.putInt("THEME_RES_ID_KEY", i3);
            bundle2.putParcelable("DATE_SELECTOR_KEY", null);
            bundle2.putParcelable("CALENDAR_CONSTRAINTS_KEY", calendarConstraints2);
            mVar.setArguments(bundle2);
            sVar = mVar;
        }
        this.t = sVar;
        this.I.setText((this.z == 1 && getResources().getConfiguration().orientation == 2) ? this.V : this.M);
        P();
        getContext();
        throw null;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStop() {
        this.t.a.clear();
        super.onStop();
    }
}
