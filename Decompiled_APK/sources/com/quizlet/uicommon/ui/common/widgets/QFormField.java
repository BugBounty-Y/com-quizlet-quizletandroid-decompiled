package com.quizlet.uicommon.ui.common.widgets;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewStub;
import android.view.accessibility.AccessibilityEvent;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.core.content.res.k;
import androidx.core.view.RunnableC1068z;
import com.quizlet.partskit.widgets.QEditText;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.widgets.QRichFormField;
import com.quizlet.quizletandroid.ui.setcreation.viewholders.l;
import com.quizlet.uicommon.ui.common.views.StatefulTintImageView;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.u;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public class QFormField extends RelativeLayout implements View.OnFocusChangeListener, TextWatcher {
    public static final int[] u = {R.attr.state_validated};
    public static final int[] v = {R.attr.state_success};
    public static final int[] w = {R.attr.state_edittext_focus};
    public final com.quizlet.quizletandroid.ui.common.databinding.f a;
    public final u b;
    public EditText c;
    public final u d;
    public final u e;
    public final u f;
    public final u g;
    public final u h;
    public final u i;
    public final u j;
    public final u k;
    public final u l;
    public final u m;
    public final u n;
    public ArrayList o;
    public d p;
    public e q;
    public boolean r;
    public boolean s;
    public int t;

    @Metadata
    public static final class SavedState extends View.BaseSavedState {

        @NotNull
        public static final Parcelable.Creator<SavedState> CREATOR = new f();
        public int a;
        public CharSequence b;
        public CharSequence c;
        public SparseArray d;

        @Override // android.view.View.BaseSavedState, android.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel out, int i) {
            Intrinsics.checkNotNullParameter(out, "out");
            super.writeToParcel(out, i);
            out.writeInt(this.a);
            TextUtils.writeToParcel(this.b, out, i);
            TextUtils.writeToParcel(this.c, out, i);
            out.writeSparseArray(this.d);
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QFormField(@NotNull Context context) {
        this(context, null, 6, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public static void a(QFormField qFormField) {
        if (qFormField.getAlignmentView() == null || qFormField.getEditText() == null) {
            return;
        }
        qFormField.getAlignmentView().setLines(Math.min(qFormField.getEditText().getMaxLines(), qFormField.getEditText().getLineCount()));
    }

    public static void b(QFormField qFormField) {
        e eVar = qFormField.q;
        Intrinsics.d(eVar);
        eVar.m(qFormField, qFormField.getFieldIcon());
    }

    private final TextView getAlignmentView() {
        return (TextView) this.n.getValue();
    }

    private static /* synthetic */ void getCurrentState$annotations() {
    }

    private final View getDefaultUnderline() {
        return (View) this.d.getValue();
    }

    private final TextView getFieldActionView() {
        Object value = this.i.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (TextView) value;
    }

    private final View getFieldActionWrapper() {
        Object value = this.h.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (View) value;
    }

    private final StatefulTintImageView getFieldIcon() {
        return (StatefulTintImageView) this.k.getValue();
    }

    private final TextView getFieldIconText() {
        Object value = this.l.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (TextView) value;
    }

    private final View getFieldIconWrapper() {
        Object value = this.j.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (View) value;
    }

    private final StatefulTintImageView getStatusIcon() {
        return (StatefulTintImageView) this.g.getValue();
    }

    private final ProgressBar getStatusProgress() {
        return (ProgressBar) this.m.getValue();
    }

    private final TextView getTextViewLabel() {
        Object value = this.e.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (TextView) value;
    }

    private final TextView getTextViewStatus() {
        Object value = this.f.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (TextView) value;
    }

    private final ViewStub getViewStub() {
        return (ViewStub) this.b.getValue();
    }

    private final void setImeOptions(int i) {
        getEditText().setImeOptions(i);
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable s) {
        Intrinsics.checkNotNullParameter(s, "s");
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence s, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(s, "s");
    }

    public final void c(View.OnFocusChangeListener onFocusChangeListener) {
        Intrinsics.checkNotNullParameter(onFocusChangeListener, "onFocusChangeListener");
        if (this.o == null) {
            this.o = new ArrayList();
        }
        ArrayList arrayList = this.o;
        if (arrayList != null) {
            arrayList.add(onFocusChangeListener);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void clearFocus() {
        getEditText().clearFocus();
        super.clearFocus();
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchRestoreInstanceState(SparseArray container) {
        Intrinsics.checkNotNullParameter(container, "container");
        dispatchThawSelfOnly(container);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchSaveInstanceState(SparseArray container) {
        Intrinsics.checkNotNullParameter(container, "container");
        dispatchFreezeSelfOnly(container);
    }

    public final void e(TextWatcher textWatcher) {
        Intrinsics.checkNotNullParameter(textWatcher, "textWatcher");
        getEditText().addTextChangedListener(textWatcher);
    }

    public final void f(AttributeSet attributeSet) {
        getViewStub().setLayoutResource(getEDITTEXT_LAYOUT_ID());
        getViewStub().inflate();
        setEditText((EditText) findViewById(getViewStub().getInflatedId()));
        getEditText().setSaveEnabled(true);
        setImportantForAccessibility(1);
        Drawable indeterminateDrawable = getStatusProgress().getIndeterminateDrawable();
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        indeterminateDrawable.setColorFilter(com.quizlet.themes.extensions.a.a(context, R.attr.colorAccent), PorterDuff.Mode.SRC_ATOP);
        getEditText().setOnFocusChangeListener(this);
        getEditText().addTextChangedListener(this);
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(attributeSet, com.quizlet.quizletandroid.ui.common.a.b);
            Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
            setLabel(typedArrayObtainStyledAttributes.getString(9));
            setHint(typedArrayObtainStyledAttributes.getString(1));
            int i = typedArrayObtainStyledAttributes.getInt(2, -1);
            if (i != -1) {
                getEditText().setMaxLines(i);
            }
            if (i == 1) {
                getEditText().setSingleLine(true);
            }
            setInputType(typedArrayObtainStyledAttributes.getInt(3, 131073));
            int i2 = typedArrayObtainStyledAttributes.getInt(6, 0);
            getEditText().setImeActionLabel(typedArrayObtainStyledAttributes.getString(5), i2);
            setImeOptions(typedArrayObtainStyledAttributes.getInt(4, 0));
            int resourceId = typedArrayObtainStyledAttributes.getResourceId(7, com.quizlet.ui.resources.designsystem.generated.a.b);
            int i3 = typedArrayObtainStyledAttributes.getInt(0, 0);
            if (!isInEditMode()) {
                getEditText().setTypeface(k.a(getContext(), resourceId), i3);
            }
            String string = typedArrayObtainStyledAttributes.getString(8);
            if (string != null) {
                getEditText().setAutofillHints(string);
            }
            typedArrayObtainStyledAttributes.recycle();
        }
        EditText editText = getEditText();
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        editText.setTextColor(com.quizlet.themes.extensions.a.a(context2, R.attr.textColor));
        i();
        getFieldActionWrapper().setOnClickListener(new a(this, 1));
        a aVar = new a(this, 2);
        getDefaultUnderline().setOnClickListener(aVar);
        getTextViewLabel().setOnClickListener(aVar);
    }

    public final void g() {
        Context context;
        Resources resources;
        if (this.p == null) {
            return;
        }
        boolean zHasFocus = hasFocus();
        String string = null;
        if (zHasFocus && getFieldActionWrapper().getVisibility() == 8) {
            View tinyView = getFieldActionWrapper();
            Intrinsics.checkNotNullParameter(tinyView, "tinyView");
            Object parent = tinyView.getParent();
            View view = parent instanceof View ? (View) parent : null;
            if (view == null) {
                timber.log.c.a.p(new RuntimeException("Attempted to attach touch target to view but no parent found"));
            } else {
                view.post(new RunnableC1068z(tinyView, 4));
            }
        }
        getFieldActionWrapper().setVisibility(zHasFocus ? 0 : 8);
        TextView fieldActionView = getFieldActionView();
        d dVar = this.p;
        Intrinsics.d(dVar);
        getContext();
        l lVar = (l) ((com.quizlet.data.repository.qclass.c) dVar).b;
        if (org.apache.commons.lang3.e.c(lVar.g)) {
            QRichFormField qRichFormField = lVar.f;
            if (qRichFormField != null && (context = qRichFormField.getContext()) != null && (resources = context.getResources()) != null) {
                string = resources.getString(R.string.select_language_button);
            }
        } else {
            string = lVar.g;
        }
        fieldActionView.setText(string);
    }

    @NotNull
    public final com.quizlet.quizletandroid.ui.common.databinding.f getBinding() {
        return this.a;
    }

    public int getEDITTEXT_LAYOUT_ID() {
        return R.layout.widget_form_field_qedit_text;
    }

    @NotNull
    public final EditText getEditText() {
        EditText editText = this.c;
        if (editText != null) {
            return editText;
        }
        Intrinsics.m("editText");
        throw null;
    }

    public final CharSequence getLabelText() {
        return getTextViewLabel().getText();
    }

    public final CharSequence getStatusText() {
        return getTextViewStatus().getText();
    }

    public final CharSequence getText() {
        return getEditText().getText();
    }

    @NotNull
    public final io.reactivex.rxjava3.core.i getTextChangeObservable() {
        EditText textChanges = getEditText();
        Intrinsics.f(textChanges, "$this$textChanges");
        C4887f c4887f = new C4887f(new com.jakewharton.rxbinding4.widget.c(textChanges), 4);
        Intrinsics.checkNotNullExpressionValue(c4887f, "skip(...)");
        return c4887f;
    }

    public final void h() {
        getStatusIcon().setVisibility(8);
        getStatusProgress().setVisibility(8);
        getFieldIconWrapper().setVisibility(8);
        if (this.r) {
            getStatusProgress().setVisibility(0);
            return;
        }
        e eVar = this.q;
        if (eVar != null) {
            if (eVar != null ? eVar.f(this) : false) {
                e eVar2 = this.q;
                Intrinsics.d(eVar2);
                if (eVar2.n() != 0) {
                    StatefulTintImageView fieldIcon = getFieldIcon();
                    e eVar3 = this.q;
                    Intrinsics.d(eVar3);
                    fieldIcon.setImageResource(eVar3.n());
                    StatefulTintImageView fieldIcon2 = getFieldIcon();
                    e eVar4 = this.q;
                    Intrinsics.d(eVar4);
                    Context context = getContext();
                    Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                    fieldIcon2.setContentDescription(eVar4.g(context));
                } else {
                    e eVar5 = this.q;
                    Intrinsics.d(eVar5);
                    eVar5.j(this);
                }
                getFieldIconWrapper().setVisibility(0);
                return;
            }
        }
        if (this.t == 1) {
            getStatusIcon().setVisibility(0);
        }
    }

    public final void i() {
        new Handler(Looper.getMainLooper()).post(new c(this, 1));
    }

    public void j(boolean z) {
        this.s = z;
        i();
    }

    public final void k(boolean z) {
        getTextViewLabel().setVisibility(z ? 8 : 0);
        getTextViewStatus().setVisibility(z ? 0 : 8);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final int[] onCreateDrawableState(int i) {
        int i2 = this.t;
        int i3 = i2 != 0 ? 1 : 0;
        int[] iArrOnCreateDrawableState = super.onCreateDrawableState((this.s ? 1 : 0) + i3 + (i2 == 1 ? 1 : 0) + i);
        if (this.s) {
            View.mergeDrawableStates(iArrOnCreateDrawableState, w);
        }
        if (i3 != 0) {
            View.mergeDrawableStates(iArrOnCreateDrawableState, u);
        }
        if (this.t == 1) {
            View.mergeDrawableStates(iArrOnCreateDrawableState, v);
        }
        Intrinsics.d(iArrOnCreateDrawableState);
        return iArrOnCreateDrawableState;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        j(z);
        ArrayList arrayList = this.o;
        if (arrayList != null) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                ((View.OnFocusChangeListener) it2.next()).onFocusChange(view, z);
            }
        }
        getAlignmentView().post(new c(this, 0));
    }

    @Override // android.view.View
    public final void onPopulateAccessibilityEvent(AccessibilityEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        super.onPopulateAccessibilityEvent(event);
        event.setSource(getEditText());
    }

    @Override // android.view.View
    public void onRestoreInstanceState(Parcelable state) {
        Intrinsics.checkNotNullParameter(state, "state");
        SavedState savedState = (SavedState) state;
        super.onRestoreInstanceState(savedState.getSuperState());
        this.t = savedState.a;
        getTextViewLabel().setText(savedState.b);
        getTextViewStatus().setText(savedState.c);
        k(this.t != 0);
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            getChildAt(i).restoreHierarchyState(savedState.d);
        }
    }

    @Override // android.view.View
    public Parcelable onSaveInstanceState() {
        Parcelable parcelableOnSaveInstanceState = super.onSaveInstanceState();
        int i = this.t;
        CharSequence labelText = getTextViewLabel().getText();
        Intrinsics.checkNotNullExpressionValue(labelText, "getText(...)");
        CharSequence statusText = getTextViewStatus().getText();
        Intrinsics.checkNotNullExpressionValue(statusText, "getText(...)");
        Intrinsics.checkNotNullParameter(labelText, "labelText");
        Intrinsics.checkNotNullParameter(statusText, "statusText");
        SavedState savedState = new SavedState(parcelableOnSaveInstanceState);
        savedState.a = i;
        savedState.b = labelText;
        savedState.c = statusText;
        savedState.d = new SparseArray();
        int childCount = getChildCount();
        for (int i2 = 0; i2 < childCount; i2++) {
            getChildAt(i2).saveHierarchyState(savedState.d);
        }
        return savedState;
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence s, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(s, "s");
        h();
        g();
        getAlignmentView().post(new c(this, 0));
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean requestFocus(int i, Rect rect) {
        return getEditText().requestFocus(i, rect);
    }

    public final void setEditText(@NotNull EditText editText) {
        Intrinsics.checkNotNullParameter(editText, "<set-?>");
        this.c = editText;
    }

    public final void setError(CharSequence charSequence) {
        this.t = -1;
        k(true ^ (charSequence == null || StringsKt.O(charSequence)));
        getTextViewStatus().setText(charSequence);
        i();
    }

    @Override // android.view.View
    public void setFocusable(boolean z) {
        getEditText().setFocusable(z);
        super.setFocusable(z);
    }

    @Override // android.view.View
    public void setFocusableInTouchMode(boolean z) {
        getEditText().setFocusableInTouchMode(z);
        super.setFocusableInTouchMode(z);
    }

    public final void setFormFieldIcon(e eVar) {
        this.q = eVar;
        CharSequence charSequenceG = null;
        if (eVar != null) {
            boolean zF = eVar != null ? eVar.f(this) : false;
            getFieldIcon().setVisibility(zF ? 0 : 8);
            getFieldIconText().setVisibility(zF ? 0 : 8);
            e eVar2 = this.q;
            if (eVar2 == null || eVar2.n() != 0) {
                StatefulTintImageView fieldIcon = getFieldIcon();
                e eVar3 = this.q;
                Intrinsics.d(eVar3);
                fieldIcon.setImageResource(eVar3.n());
                StatefulTintImageView fieldIcon2 = getFieldIcon();
                e eVar4 = this.q;
                if (eVar4 != null) {
                    Context context = getContext();
                    Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                    charSequenceG = eVar4.g(context);
                }
                fieldIcon2.setContentDescription(charSequenceG);
                getFieldIconText().setVisibility(8);
            } else {
                e eVar5 = this.q;
                if (eVar5 != null) {
                    eVar5.j(this);
                    timber.log.c.a.e(new IllegalStateException("QFormFieldIcon lacks icon or string"));
                } else {
                    TextView fieldIconText = getFieldIconText();
                    e eVar6 = this.q;
                    Intrinsics.d(eVar6);
                    eVar6.j(this);
                    fieldIconText.setText(0);
                    getFieldIcon().setVisibility(8);
                }
            }
            getFieldIconWrapper().setOnClickListener(new a(this, 0));
        } else {
            getFieldIconText().setVisibility(8);
            getFieldIcon().setVisibility(8);
            getFieldIcon().setImageDrawable(null);
            getFieldIconText().setText((CharSequence) null);
            getFieldIconWrapper().setOnClickListener(null);
        }
        h();
    }

    public final void setFormIconTintColor(int i) {
        getFieldIcon().setTintColor(i);
    }

    public final void setFormfieldAction(d dVar) {
        this.p = dVar;
        if (dVar == null) {
            getFieldActionWrapper().setVisibility(8);
        } else {
            g();
        }
    }

    public final void setHint(CharSequence charSequence) {
        getEditText().setHint(charSequence);
    }

    public final void setInputType(int i) {
        getEditText().setInputType(i);
    }

    public final void setLabel(CharSequence charSequence) {
        getTextViewLabel().setText(charSequence);
        getEditText().setContentDescription(charSequence);
        EditText editText = getEditText();
        QEditText qEditText = editText instanceof QEditText ? (QEditText) editText : null;
        if (qEditText != null) {
            qEditText.setAccessibilityLabel(charSequence);
        }
    }

    public final void setLoading(boolean z) {
        this.r = z;
        i();
    }

    public final void setMaxLines(int i) {
        getEditText().setMaxLines(i);
    }

    public final void setSuccess(CharSequence charSequence) {
        this.t = 1;
        k(true ^ (charSequence == null || StringsKt.O(charSequence)));
        getTextViewStatus().setText(charSequence);
        i();
    }

    public final void setText(CharSequence charSequence) {
        getEditText().setText(charSequence);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QFormField(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ QFormField(Context context, AttributeSet attributeSet, int i, int i2) {
        this(context, (i & 2) != 0 ? null : attributeSet, 0);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public QFormField(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, 0);
        Intrinsics.checkNotNullParameter(context, "context");
        com.quizlet.quizletandroid.ui.common.databinding.f fVarA = com.quizlet.quizletandroid.ui.common.databinding.f.a(LayoutInflater.from(getContext()), this);
        Intrinsics.checkNotNullExpressionValue(fVarA, "inflate(...)");
        this.a = fVarA;
        final int i2 = 10;
        this.b = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i3 = 13;
        this.d = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i3) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i4 = 14;
        this.e = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i4) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i5 = 15;
        this.f = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i5) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i6 = 16;
        this.g = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i6) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i7 = 17;
        this.h = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i7) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i8 = 0;
        this.i = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i8) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i9 = 1;
        this.j = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i9) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i10 = 2;
        this.k = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i10) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i11 = 3;
        this.l = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i11) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i12 = 11;
        this.m = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i12) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i13 = 12;
        this.n = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i13) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        f(attributeSet);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public QFormField(Context context, int i) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        com.quizlet.quizletandroid.ui.common.databinding.f fVarA = com.quizlet.quizletandroid.ui.common.databinding.f.a(LayoutInflater.from(getContext()), this);
        Intrinsics.checkNotNullExpressionValue(fVarA, "inflate(...)");
        this.a = fVarA;
        final int i2 = 4;
        this.b = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i3 = 7;
        this.d = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i3) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i4 = 14;
        this.e = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i4) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i5 = 15;
        this.f = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i5) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i6 = 8;
        this.g = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i6) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i7 = 17;
        this.h = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i7) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i8 = 0;
        this.i = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i8) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i9 = 1;
        this.j = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i9) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i10 = 9;
        this.k = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i10) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i11 = 3;
        this.l = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i11) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i12 = 5;
        this.m = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i12) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        final int i13 = 6;
        this.n = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.widgets.b
            public final /* synthetic */ QFormField b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i13) {
                    case 0:
                        return this.b.a.d;
                    case 1:
                        return this.b.a.h;
                    case 2:
                        StatefulTintImageView widgetFormFieldActionIcon = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon;
                    case 3:
                        return this.b.a.c;
                    case 4:
                        ViewStub widgetFormFieldEdittextStub = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub;
                    case 5:
                        ProgressBar widgetFormFieldStatusProgress = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress;
                    case 6:
                        TextView widgetFormFieldTextAlignmentView = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView;
                    case 7:
                        View widgetFormFieldDefaultUnderline = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline;
                    case 8:
                        StatefulTintImageView widgetFormFieldStatusIcon = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon;
                    case 9:
                        StatefulTintImageView widgetFormFieldActionIcon2 = this.b.a.b;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldActionIcon2, "widgetFormFieldActionIcon");
                        return widgetFormFieldActionIcon2;
                    case 10:
                        ViewStub widgetFormFieldEdittextStub2 = this.b.a.g;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldEdittextStub2, "widgetFormFieldEdittextStub");
                        return widgetFormFieldEdittextStub2;
                    case 11:
                        ProgressBar widgetFormFieldStatusProgress2 = this.b.a.l;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusProgress2, "widgetFormFieldStatusProgress");
                        return widgetFormFieldStatusProgress2;
                    case 12:
                        TextView widgetFormFieldTextAlignmentView2 = this.b.a.o;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldTextAlignmentView2, "widgetFormFieldTextAlignmentView");
                        return widgetFormFieldTextAlignmentView2;
                    case 13:
                        View widgetFormFieldDefaultUnderline2 = this.b.a.f;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldDefaultUnderline2, "widgetFormFieldDefaultUnderline");
                        return widgetFormFieldDefaultUnderline2;
                    case 14:
                        return this.b.a.i;
                    case 15:
                        return this.b.a.m;
                    case 16:
                        StatefulTintImageView widgetFormFieldStatusIcon2 = this.b.a.k;
                        Intrinsics.checkNotNullExpressionValue(widgetFormFieldStatusIcon2, "widgetFormFieldStatusIcon");
                        return widgetFormFieldStatusIcon2;
                    default:
                        return this.b.a.e;
                }
            }
        });
        setId(i);
        f(null);
    }
}
