package com.quizlet.richtext.ui.toolbar;

import android.content.Context;
import android.text.Editable;
import android.text.style.CharacterStyle;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import android.widget.ToggleButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.richtext.ui.QRichEditText;
import com.quizlet.uicommon.ui.common.views.QuizletPlusBadge;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.wordpress.aztec.G;
import org.wordpress.aztec.p;

@Metadata
/* loaded from: classes3.dex */
public final class QRichTextToolbar extends RelativeLayout implements org.wordpress.aztec.toolbar.a, p {
    public QRichEditText a;
    public final QuizletPlusBadge b;
    public com.quizlet.richtext.rendering.b c;
    public a d;
    public Function1 e;
    public final LinkedHashSet f;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QRichTextToolbar(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final ArrayList<G> getSelectedFormats() {
        ArrayList<G> arrayList = new ArrayList<>();
        for (b bVar : this.f) {
            if (bVar.a.isChecked()) {
                arrayList.add(CollectionsKt.K(bVar.b.b));
            }
        }
        return arrayList;
    }

    /* JADX WARN: Removed duplicated region for block: B:114:0x0258  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x0261  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x02da  */
    /* JADX WARN: Removed duplicated region for block: B:341:0x085c  */
    /* JADX WARN: Removed duplicated region for block: B:342:0x085e  */
    /* JADX WARN: Removed duplicated region for block: B:347:0x087d  */
    /* JADX WARN: Removed duplicated region for block: B:348:0x087f  */
    /* JADX WARN: Removed duplicated region for block: B:350:0x0882  */
    /* JADX WARN: Removed duplicated region for block: B:365:0x090e  */
    /* JADX WARN: Removed duplicated region for block: B:379:0x099b  */
    /* JADX WARN: Removed duplicated region for block: B:387:0x09c4  */
    /* JADX WARN: Removed duplicated region for block: B:418:0x0a52  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(org.wordpress.aztec.toolbar.c r30) {
        /*
            Method dump skipped, instructions count: 2695
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.richtext.ui.toolbar.QRichTextToolbar.a(org.wordpress.aztec.toolbar.c):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x006f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.ArrayList b(android.text.style.CharacterStyle[] r8) {
        /*
            r7 = this;
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            int r1 = r8.length
            r2 = 0
        L7:
            if (r2 >= r1) goto L7e
            r3 = r8[r2]
            boolean r4 = r3 instanceof org.wordpress.aztec.spans.AztecStyleBoldSpan
            if (r4 != 0) goto L74
            boolean r4 = r3 instanceof org.wordpress.aztec.spans.AztecStyleStrongSpan
            if (r4 == 0) goto L14
            goto L74
        L14:
            boolean r4 = r3 instanceof org.wordpress.aztec.spans.AztecStyleItalicSpan
            if (r4 != 0) goto L71
            boolean r4 = r3 instanceof org.wordpress.aztec.spans.AztecStyleEmphasisSpan
            if (r4 == 0) goto L1d
            goto L71
        L1d:
            boolean r4 = r3 instanceof org.wordpress.aztec.spans.AztecUnderlineSpan
            if (r4 == 0) goto L24
            com.quizlet.richtext.ui.toolbar.c r3 = com.quizlet.richtext.ui.toolbar.c.e
            goto L76
        L24:
            boolean r4 = r3 instanceof org.wordpress.aztec.spans.AztecBackgroundColorSpan
            r5 = 0
            if (r4 == 0) goto L6f
            org.wordpress.aztec.spans.AztecBackgroundColorSpan r3 = (org.wordpress.aztec.spans.AztecBackgroundColorSpan) r3
            int r3 = r3.a
            com.quizlet.richtext.rendering.b r4 = r7.c
            if (r4 == 0) goto L43
            com.quizlet.quizletandroid.ui.setcreation.managers.n r4 = (com.quizlet.quizletandroid.ui.setcreation.managers.n) r4
            java.lang.Object r4 = r4.b
            com.quizlet.data.repository.set.f r4 = (com.quizlet.data.repository.set.f) r4
            r6 = 2130969178(0x7f04025a, float:1.754703E38)
            int r4 = r4.g(r6)
            if (r3 != r4) goto L43
            com.quizlet.richtext.ui.toolbar.c r3 = com.quizlet.richtext.ui.toolbar.c.f
            goto L76
        L43:
            com.quizlet.richtext.rendering.b r4 = r7.c
            if (r4 == 0) goto L59
            com.quizlet.quizletandroid.ui.setcreation.managers.n r4 = (com.quizlet.quizletandroid.ui.setcreation.managers.n) r4
            java.lang.Object r4 = r4.b
            com.quizlet.data.repository.set.f r4 = (com.quizlet.data.repository.set.f) r4
            r6 = 2130969219(0x7f040283, float:1.7547114E38)
            int r4 = r4.g(r6)
            if (r3 != r4) goto L59
            com.quizlet.richtext.ui.toolbar.c r3 = com.quizlet.richtext.ui.toolbar.c.g
            goto L76
        L59:
            com.quizlet.richtext.rendering.b r4 = r7.c
            if (r4 == 0) goto L6f
            com.quizlet.quizletandroid.ui.setcreation.managers.n r4 = (com.quizlet.quizletandroid.ui.setcreation.managers.n) r4
            java.lang.Object r4 = r4.b
            com.quizlet.data.repository.set.f r4 = (com.quizlet.data.repository.set.f) r4
            r6 = 2130969252(0x7f0402a4, float:1.754718E38)
            int r4 = r4.g(r6)
            if (r3 != r4) goto L6f
            com.quizlet.richtext.ui.toolbar.c r3 = com.quizlet.richtext.ui.toolbar.c.h
            goto L76
        L6f:
            r3 = r5
            goto L76
        L71:
            com.quizlet.richtext.ui.toolbar.c r3 = com.quizlet.richtext.ui.toolbar.c.d
            goto L76
        L74:
            com.quizlet.richtext.ui.toolbar.c r3 = com.quizlet.richtext.ui.toolbar.c.c
        L76:
            if (r3 == 0) goto L7b
            r0.add(r3)
        L7b:
            int r2 = r2 + 1
            goto L7
        L7e:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.richtext.ui.toolbar.QRichTextToolbar.b(android.text.style.CharacterStyle[]):java.util.ArrayList");
    }

    public final void c(int i, int i2) {
        Editable editableText;
        List listG;
        try {
            QRichEditText qRichEditText = this.a;
            LinkedHashSet<b> linkedHashSet = this.f;
            if (qRichEditText != null && (editableText = qRichEditText.getEditableText()) != null) {
                CharacterStyle[] characterStyleArr = (CharacterStyle[]) editableText.getSpans((i != i2 || i == 0) ? i : i - 1, i2, CharacterStyle.class);
                if (characterStyleArr != null && (listG = CollectionsKt.G(b(characterStyleArr))) != null) {
                    for (b bVar : linkedHashSet) {
                        ToggleButton toggleButton = bVar.a;
                        c cVar = bVar.b;
                        toggleButton.setChecked(listG.contains(cVar));
                        if (i == i2 && bVar.a.isChecked()) {
                            a(cVar);
                        }
                    }
                    return;
                }
            }
            Iterator it2 = linkedHashSet.iterator();
            while (it2.hasNext()) {
                ((b) it2.next()).a.setChecked(false);
            }
        } catch (IndexOutOfBoundsException e) {
            timber.log.c.a.p(e);
        }
    }

    public final com.quizlet.richtext.rendering.b getHighlightColorResolver() {
        return this.c;
    }

    public final Function1<org.wordpress.aztec.toolbar.c, Unit> getToolbarActionClickListener() {
        return this.e;
    }

    public final a getToolbarListener() {
        return this.d;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.a = null;
        this.f.clear();
    }

    public final void setHighlightColorResolver(com.quizlet.richtext.rendering.b bVar) {
        this.c = bVar;
    }

    public final void setIsLocked(boolean z) {
        QuizletPlusBadge quizletPlusBadge = this.b;
        Intrinsics.checkNotNullParameter(quizletPlusBadge, "<this>");
        quizletPlusBadge.setVisibility(!z ? 8 : 0);
    }

    public final void setToolbarActionClickListener(Function1<? super org.wordpress.aztec.toolbar.c, Unit> function1) {
        this.e = function1;
    }

    public void setToolbarListener(@NotNull org.wordpress.aztec.toolbar.b listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QRichTextToolbar(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public final void setToolbarListener(a aVar) {
        this.d = aVar;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public QRichTextToolbar(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        this.f = new LinkedHashSet();
        LayoutInflater.from(context).inflate(R.layout.q_rich_text_toolbar, (ViewGroup) this, true);
        this.b = (QuizletPlusBadge) findViewById(R.id.rtPlusBadge);
        for (c cVar : c.values()) {
            ToggleButton toggleButton = (ToggleButton) findViewById(cVar.a);
            if (toggleButton != null) {
                toggleButton.setOnClickListener(new com.braze.ui.inappmessage.views.a(27, this, cVar));
            }
            Intrinsics.d(toggleButton);
            this.f.add(new b(toggleButton, cVar));
        }
    }
}
