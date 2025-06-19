package com.quizlet.quizletandroid.ui.setcreation.viewholders;

import android.content.Context;
import android.text.Editable;
import android.text.style.CharacterStyle;
import android.widget.EditText;
import android.widget.LinearLayout;
import com.quizlet.api.model.TermContentSuggestions;
import com.quizlet.quizletandroid.ui.common.widgets.QRichFormField;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l {
    public String a;
    public String b;
    public final boolean c;
    public String d;
    public boolean e;
    public final QRichFormField f;
    public String g;
    public final androidx.work.impl.model.c h;
    public final LinearLayout i;
    public final j j;
    public final /* synthetic */ m k;

    public l(m mVar, boolean z, QRichFormField qRichFormField, LinearLayout linearLayout, androidx.work.impl.model.c userProps) {
        Intrinsics.checkNotNullParameter("", "mValue");
        Intrinsics.checkNotNullParameter("", "mJsonValue");
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        this.k = mVar;
        this.a = "";
        this.b = "";
        this.c = z;
        this.h = userProps;
        this.i = linearLayout;
        this.j = new j(this);
        if (qRichFormField != null) {
            qRichFormField.setFormfieldAction(new com.quizlet.data.repository.qclass.c(27, this, mVar));
            qRichFormField.c(new com.quizlet.quizletandroid.ui.common.widgets.f(1, mVar, this));
            qRichFormField.getEditText().setOnKeyListener(new com.onetrust.otpublishers.headless.UI.TVUI.adapter.m(this, 2));
        } else {
            qRichFormField = null;
        }
        this.f = qRichFormField;
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x007f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(java.lang.String r9, java.lang.String r10, com.quizlet.db.data.models.wrappers.RawJsonObject r11) {
        /*
            r8 = this;
            com.quizlet.quizletandroid.ui.setcreation.viewholders.j r0 = r8.j
            com.quizlet.quizletandroid.ui.common.widgets.QRichFormField r1 = r8.f
            if (r1 == 0) goto L12
            java.lang.String r2 = "textWatcher"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            android.widget.EditText r2 = r1.getEditText()
            r2.removeTextChangedListener(r0)
        L12:
            java.lang.String r2 = ""
            if (r9 != 0) goto L17
            r9 = r2
        L17:
            r8.a = r9
            r9 = 0
            if (r11 == 0) goto L21
            java.lang.String r3 = r11.getValue()
            goto L22
        L21:
            r3 = r9
        L22:
            if (r3 != 0) goto L25
            goto L26
        L25:
            r2 = r3
        L26:
            r8.b = r2
            if (r1 == 0) goto L2f
            java.lang.CharSequence r2 = r1.getText()
            goto L30
        L2f:
            r2 = r9
        L30:
            java.lang.String r2 = java.lang.String.valueOf(r2)
            if (r1 == 0) goto L3b
            java.lang.String r3 = r1.getRichTextJson()
            goto L3c
        L3b:
            r3 = r9
        L3c:
            java.lang.String r4 = r8.a
            boolean r2 = r4.equals(r2)
            if (r2 == 0) goto L52
            java.lang.String r2 = r8.b
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L52
            java.lang.String r2 = r8.d
            if (r2 != 0) goto L52
            goto Lcd
        L52:
            android.text.SpannableStringBuilder r2 = new android.text.SpannableStringBuilder
            java.lang.String r3 = r8.a
            r2.<init>(r3)
            r3 = 0
            if (r10 == 0) goto L7f
            int r4 = r10.length()
            if (r4 != 0) goto L63
            goto L7f
        L63:
            java.lang.String r4 = r8.a
            java.util.Locale r5 = java.util.Locale.ROOT
            java.lang.String r4 = r4.toLowerCase(r5)
            java.lang.String r6 = "toLowerCase(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r6)
            java.lang.String r5 = r10.toLowerCase(r5)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            boolean r4 = kotlin.text.D.r(r4, r5, r3)
            if (r4 == 0) goto L7f
            r4 = 1
            goto L80
        L7f:
            r4 = r3
        L80:
            if (r4 == 0) goto Lac
            android.text.style.ForegroundColorSpan r5 = new android.text.style.ForegroundColorSpan
            com.quizlet.quizletandroid.ui.setcreation.viewholders.m r6 = r8.k
            android.view.View r6 = r6.itemView
            android.content.Context r6 = r6.getContext()
            java.lang.String r7 = "getContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r7)
            r7 = 2130970420(0x7f040734, float:1.754955E38)
            int r6 = com.quizlet.themes.extensions.a.a(r6, r7)
            r5.<init>(r6)
            if (r10 == 0) goto La1
            int r3 = r10.length()
        La1:
            java.lang.String r6 = r8.a
            int r6 = r6.length()
            r7 = 18
            r2.setSpan(r5, r3, r6, r7)
        Lac:
            if (r1 == 0) goto Lb1
            r1.n(r11, r2)
        Lb1:
            if (r4 == 0) goto Lb4
            goto Lb5
        Lb4:
            r10 = r9
        Lb5:
            r8.d = r10
            if (r1 == 0) goto Lc8
            android.widget.EditText r9 = r1.getEditText()
            android.widget.EditText r10 = r1.getEditText()
            int r10 = r10.length()
            r9.setSelection(r10)
        Lc8:
            if (r1 == 0) goto Lcd
            r1.e(r0)
        Lcd:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setcreation.viewholders.l.a(java.lang.String, java.lang.String, com.quizlet.db.data.models.wrappers.RawJsonObject):void");
    }

    public final void b() {
        EditText editText;
        Editable text;
        EditText editText2;
        Editable text2;
        QRichFormField qRichFormField = this.f;
        if (qRichFormField != null && (editText = qRichFormField.getEditText()) != null && (text = editText.getText()) != null) {
            Object[] spans = text.getSpans(0, this.a.length(), Object.class);
            if (spans != null) {
                for (Object obj : spans) {
                    if ((obj instanceof CharacterStyle) && qRichFormField != null && (editText2 = qRichFormField.getEditText()) != null && (text2 = editText2.getText()) != null) {
                        text2.removeSpan(obj);
                    }
                }
            }
        }
        this.d = null;
    }

    public final void c(List list) {
        LinearLayout linearLayout = this.i;
        linearLayout.removeAllViews();
        if (!this.e || list == null || list.isEmpty()) {
            return;
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            TermContentSuggestions.Suggestions suggestions = (TermContentSuggestions.Suggestions) it2.next();
            String text = suggestions.text;
            if (text != null) {
                Intrinsics.checkNotNullExpressionValue(text, "text");
                if (text.length() != 0) {
                    m mVar = this.k;
                    Context context = mVar.itemView.getContext();
                    Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                    com.quizlet.quizletandroid.ui.setcreation.views.a aVar = new com.quizlet.quizletandroid.ui.setcreation.views.a(context, 0);
                    String text2 = suggestions.text;
                    Intrinsics.checkNotNullExpressionValue(text2, "text");
                    aVar.a(text2, this.a);
                    aVar.setOnClickListener(new com.braze.ui.contentcards.view.a(this, suggestions, mVar, 5));
                    linearLayout.addView(aVar);
                }
            }
        }
    }
}
