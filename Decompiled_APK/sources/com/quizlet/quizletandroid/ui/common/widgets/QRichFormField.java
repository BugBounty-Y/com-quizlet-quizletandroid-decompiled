package com.quizlet.quizletandroid.ui.common.widgets;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.util.AttributeSet;
import android.view.View;
import android.widget.EditText;
import com.quizlet.db.data.models.wrappers.RawJsonObject;
import com.quizlet.quizletandroid.R;
import com.quizlet.richtext.ui.QRichEditText;
import com.quizlet.richtext.ui.toolbar.QRichTextToolbar;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QRichFormField extends QFormField implements com.quizlet.richtext.ui.toolbar.a {
    public com.quizlet.richtext.rendering.c x;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QRichFormField(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final QRichEditText getRichEditText() {
        EditText editText = getEditText();
        Intrinsics.e(editText, "null cannot be cast to non-null type com.quizlet.richtext.ui.QRichEditText");
        return (QRichEditText) editText;
    }

    public static void l(QRichFormField qRichFormField, QRichTextToolbar qRichTextToolbar, View view, boolean z) {
        if (z) {
            qRichFormField.getRichEditText().setToolbar(qRichTextToolbar);
            qRichTextToolbar.setToolbarListener((com.quizlet.richtext.ui.toolbar.a) qRichFormField);
            QRichEditText richEditText = qRichFormField.getRichEditText();
            qRichTextToolbar.a = richEditText;
            if (richEditText != null) {
                richEditText.setOnSelectionChangedListener(qRichTextToolbar);
                qRichTextToolbar.c(richEditText.getSelectionStart(), richEditText.getSelectionEnd());
            }
        } else {
            qRichFormField.getRichEditText().setToolbar(null);
            qRichTextToolbar.setToolbarListener((com.quizlet.richtext.ui.toolbar.a) null);
        }
        qRichFormField.onFocusChange(view, z);
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.QFormField
    public int getEDITTEXT_LAYOUT_ID() {
        return R.layout.widget_form_field_rich_edit_text;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:55:0x015e  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0164  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0168  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x016b A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String getRichTextJson() {
        /*
            Method dump skipped, instructions count: 489
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.common.widgets.QRichFormField.getRichTextJson():java.lang.String");
    }

    public final com.quizlet.richtext.rendering.c getRichTextRenderer() {
        return this.x;
    }

    public final void m() {
        QRichEditText richEditText = getRichEditText();
        if (richEditText.getSelectionStart() != richEditText.getSelectionEnd()) {
            int selectionStart = richEditText.getSelectionStart();
            int selectionEnd = richEditText.getSelectionEnd();
            n(new RawJsonObject(getRichTextJson()), new SpannableStringBuilder(richEditText.getText()));
            richEditText.setSelection(selectionStart, selectionEnd);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v3, types: [java.lang.CharSequence] */
    public final void n(RawJsonObject rawJsonObject, SpannableStringBuilder builder) {
        ?? A;
        String value;
        Intrinsics.checkNotNullParameter(builder, "builder");
        com.quizlet.richtext.model.a aVar = (rawJsonObject == null || (value = rawJsonObject.getValue()) == null) ? null : new com.quizlet.richtext.model.a(value);
        getRichEditText().m = true;
        getRichEditText().n = true;
        QRichEditText richEditText = getRichEditText();
        com.quizlet.richtext.rendering.c cVar = this.x;
        if (cVar != null && (A = ((com.quizlet.richtext.rendering.a) cVar).a(aVar, builder)) != 0) {
            builder = A;
        }
        richEditText.setText(builder);
        getRichEditText().n = false;
        getRichEditText().m = false;
    }

    public final void setRichTextRenderer(com.quizlet.richtext.rendering.c cVar) {
        this.x = cVar;
    }

    public final void setToolbar(@NotNull QRichTextToolbar toolbar) {
        Intrinsics.checkNotNullParameter(toolbar, "toolbar");
        getRichEditText().setOnFocusChangeListener(new f(0, this, toolbar));
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QRichFormField(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public QRichFormField(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
    }
}
