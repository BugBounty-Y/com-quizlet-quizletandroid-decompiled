package org.wordpress.aztec;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.os.Build;
import android.os.Bundle;
import android.os.Looper;
import android.os.Parcel;
import android.os.Parcelable;
import android.provider.Settings;
import android.text.Editable;
import android.text.InputFilter;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.MovementMethod;
import android.text.style.SuggestionSpan;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.BaseInputConnection;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.app.C0051g;
import androidx.appcompat.app.DialogInterfaceC0052h;
import androidx.appcompat.widget.C0116w;
import androidx.appcompat.widget.U0;
import androidx.compose.ui.text.C0981a;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import com.google.android.gms.internal.mlkit_vision_camera.K2;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import com.quizlet.edgy.ui.fragment.C4197k;
import com.quizlet.quizletandroid.R;
import com.quizlet.richtext.ui.toolbar.QRichTextToolbar;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;
import org.wordpress.aztec.source.SourceViewEditText;
import org.wordpress.aztec.spans.AbstractC5156d;
import org.wordpress.aztec.spans.AbstractC5167o;
import org.wordpress.aztec.spans.AztecListSpan;
import org.wordpress.aztec.spans.AztecOrderedListSpan;
import org.wordpress.aztec.spans.AztecPreformatSpan;
import org.wordpress.aztec.spans.AztecTaskListSpan;
import org.wordpress.aztec.spans.AztecTaskListSpanAligned;
import org.wordpress.aztec.spans.AztecURLSpan;
import org.wordpress.aztec.spans.AztecUnorderedListSpan;
import org.wordpress.aztec.spans.C5153a;
import org.wordpress.aztec.spans.C5154b;
import org.wordpress.aztec.spans.C5155c;
import org.wordpress.aztec.spans.C5160h;
import org.wordpress.aztec.spans.C5162j;
import org.wordpress.aztec.spans.C5163k;
import org.wordpress.aztec.spans.C5164l;
import org.wordpress.aztec.spans.C5168p;
import org.wordpress.aztec.spans.C5170s;
import org.wordpress.aztec.spans.C5171t;
import org.wordpress.aztec.spans.C5172u;
import org.wordpress.aztec.spans.EnumC5157e;
import org.wordpress.aztec.spans.T;
import org.wordpress.aztec.spans.W;
import org.wordpress.aztec.spans.X;

/* loaded from: classes3.dex */
public class AztecText extends C0116w implements TextWatcher, W {
    public static final EnumC5145a q1 = EnumC5145a.a;
    public static int r1;
    public final EnumC5145a A;
    public boolean B;
    public boolean C;
    public int D;
    public org.wordpress.aztec.toolbar.a E;
    public final ArrayList F;
    public int G;
    public int H;
    public boolean I;
    public z J;
    public org.wordpress.aztec.formatting.l K;
    public org.wordpress.aztec.formatting.i L;
    public org.wordpress.aztec.formatting.n M;
    public org.wordpress.aztec.formatting.p V;
    public ArrayList W;
    public int c1;
    public int d1;
    public int e1;
    public int f1;
    public final Regex g;
    public int g1;
    public final Regex h;
    public int h1;
    public boolean i;
    public org.wordpress.aztec.watchers.event.sequence.a i1;
    public int j;
    public org.wordpress.aztec.watchers.event.text.d j1;
    public DialogInterfaceC0052h k;
    public final androidx.camera.camera2.internal.concurrent.a k1;
    public DialogInterfaceC0052h l;
    public boolean l1;
    public boolean m;
    public final C5147c m1;
    public boolean n;
    public int n1;
    public boolean o;
    public int o1;
    public boolean p;
    public org.wordpress.aztec.formatting.d p1;
    public boolean q;
    public boolean r;
    public byte[] s;
    public p t;
    public boolean u;
    public boolean v;
    public boolean w;
    public boolean x;
    public boolean y;
    public boolean z;

    @Metadata
    public static final class SavedState extends View.BaseSavedState {

        @NotNull
        public static final Parcelable.Creator<SavedState> CREATOR = new t();
        public Bundle a;

        @Override // android.view.View.BaseSavedState, android.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel out, int i) {
            Intrinsics.checkNotNullParameter(out, "out");
            super.writeToParcel(out, i);
            out.writeBundle(this.a);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecText(@NotNull Context context) throws Resources.NotFoundException {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        kotlin.text.s sVar = kotlin.text.s.c;
        kotlin.text.s[] elements = {sVar, kotlin.text.s.b};
        Intrinsics.checkNotNullParameter(elements, "elements");
        this.g = new Regex(C4933y.T(elements));
        this.h = new Regex("^(?:[a-z]+:|#|\\?|\\.|/)", sVar);
        this.i = getResources().getBoolean(R.bool.history_enable);
        this.j = getResources().getInteger(R.integer.history_size);
        this.o = true;
        this.s = new byte[0];
        this.x = getResources().getBoolean(R.bool.comments_visible);
        this.y = true;
        this.B = true;
        this.D = -1;
        this.F = new ArrayList();
        this.W = new ArrayList();
        this.i1 = new org.wordpress.aztec.watchers.event.sequence.a(this);
        this.j1 = new org.wordpress.aztec.watchers.event.text.d();
        this.k1 = new androidx.camera.camera2.internal.concurrent.a(this);
        this.l1 = true;
        this.m1 = new C5147c();
        this.A = q1;
        k(null);
    }

    public static boolean b(AztecText this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        int selectionStart = this$0.getSelectionStart();
        int selectionEnd = this$0.getSelectionEnd();
        if (selectionEnd - selectionStart != 1) {
            return false;
        }
        Rect boxContainingSelectionCoordinates = this$0.getBoxContainingSelectionCoordinates();
        int i = boxContainingSelectionCoordinates.left;
        int i2 = this$0.n1;
        if (i >= i2) {
            return false;
        }
        int i3 = boxContainingSelectionCoordinates.top;
        int i4 = this$0.o1;
        if (i3 >= i4 || boxContainingSelectionCoordinates.right <= i2 || boxContainingSelectionCoordinates.bottom <= i4) {
            return false;
        }
        Object[] spans = this$0.getEditableText().getSpans(selectionStart, selectionEnd, C5172u.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        if (spans.length != 1) {
            Object[] spans2 = this$0.getEditableText().getSpans(selectionStart, selectionEnd, C5170s.class);
            Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
            if (spans2.length != 1) {
                return false;
            }
        }
        return true;
    }

    public static final void c(AztecText aztecText, AztecTaskListSpan aztecTaskListSpan) {
        AztecTaskListSpan aztecTaskListSpan2;
        int selectionStart = aztecText.getSelectionStart();
        int selectionEnd = aztecText.getSelectionEnd();
        int spanStart = aztecText.getEditableText().getSpanStart(aztecTaskListSpan);
        int spanEnd = aztecText.getEditableText().getSpanEnd(aztecTaskListSpan);
        int spanFlags = aztecText.getEditableText().getSpanFlags(aztecTaskListSpan);
        aztecTaskListSpan.g = null;
        aztecText.getEditableText().removeSpan(aztecTaskListSpan);
        if (aztecTaskListSpan instanceof AztecTaskListSpanAligned) {
            int i = aztecTaskListSpan.d;
            Context context = aztecText.getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            aztecTaskListSpan2 = new AztecTaskListSpanAligned(i, aztecTaskListSpan.e, context, aztecTaskListSpan.f, ((AztecTaskListSpanAligned) aztecTaskListSpan).l);
        } else {
            int i2 = aztecTaskListSpan.d;
            Context context2 = aztecText.getContext();
            Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
            aztecTaskListSpan2 = new AztecTaskListSpan(i2, aztecTaskListSpan.e, context2, aztecTaskListSpan.f);
        }
        aztecTaskListSpan2.g = new u(aztecText, 1);
        aztecText.getEditableText().setSpan(aztecTaskListSpan2, spanStart, spanEnd, spanFlags);
        aztecText.setSelection(selectionStart, selectionEnd);
    }

    public static void e(SpannableStringBuilder text) {
        Intrinsics.checkNotNullParameter(text, "text");
        BaseInputConnection.removeComposingSpans(text);
        Object[] spans = text.getSpans(0, text.length(), SuggestionSpan.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        for (Object obj : spans) {
            text.removeSpan((SuggestionSpan) obj);
        }
    }

    private final Rect getBoxContainingSelectionCoordinates() {
        int[] iArr = new int[2];
        getLocationOnScreen(iArr);
        int lineForOffset = getLayout().getLineForOffset(getSelectionStart());
        int lineForOffset2 = getLayout().getLineForOffset(getSelectionEnd());
        Rect rect = new Rect();
        getLineBounds(lineForOffset, rect);
        if (lineForOffset2 != lineForOffset) {
            Rect rect2 = new Rect();
            getLineBounds(lineForOffset2, rect2);
            return new Rect((rect.left + iArr[0]) - getScrollX(), (rect.top + iArr[1]) - getScrollY(), (rect2.right + iArr[0]) - getScrollX(), (rect2.bottom + iArr[1]) - getScrollY());
        }
        return new Rect(((((int) getLayout().getPrimaryHorizontal(getSelectionStart())) + iArr[0]) - getScrollX()) + rect.left, (rect.top + iArr[1]) - getScrollY(), ((((int) getLayout().getPrimaryHorizontal(getSelectionEnd())) + iArr[0]) - getScrollX()) + rect.left, (rect.bottom + iArr[1]) - getScrollY());
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable text) {
        Intrinsics.checkNotNullParameter(text, "text");
        if (this.m) {
            r1--;
            return;
        }
        if (l()) {
            org.wordpress.aztec.watchers.event.text.a aVar = new org.wordpress.aztec.watchers.event.text.a(Editable.Factory.getInstance().newEditable(getEditableText()));
            org.wordpress.aztec.watchers.event.text.d dVar = this.j1;
            dVar.getClass();
            Intrinsics.checkNotNullParameter(aVar, "<set-?>");
            dVar.c = aVar;
            this.i1.add(this.j1.a());
        }
        r1--;
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence text, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(text, "text");
        r1++;
        if (this.u && l()) {
            org.wordpress.aztec.watchers.event.text.b bVar = new org.wordpress.aztec.watchers.event.text.b(new SpannableStringBuilder(text), i, i2, i3);
            org.wordpress.aztec.watchers.event.text.d dVar = this.j1;
            dVar.getClass();
            Intrinsics.checkNotNullParameter(bVar, "<set-?>");
            dVar.a = bVar;
        }
    }

    public final void d(Editable editable, int i, int i2) {
        Intrinsics.checkNotNullParameter(editable, "editable");
        AztecTaskListSpan[] aztecTaskListSpanArr = (AztecTaskListSpan[]) editable.getSpans(i, i2, AztecTaskListSpan.class);
        Intrinsics.d(aztecTaskListSpanArr);
        for (AztecTaskListSpan aztecTaskListSpan : aztecTaskListSpanArr) {
            if (aztecTaskListSpan.g == null) {
                aztecTaskListSpan.g = new u(this, 0);
            }
        }
    }

    @Override // android.view.View
    public final boolean dispatchHoverEvent(MotionEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (this.k1.H(event)) {
            return true;
        }
        return super.dispatchHoverEvent(event);
    }

    public final boolean f(int i, int i2, G textFormat) {
        int i3;
        Intrinsics.checkNotNullParameter(textFormat, "format");
        if (textFormat == x.b || textFormat == x.c || textFormat == x.d || textFormat == x.e || textFormat == x.f || textFormat == x.g) {
            org.wordpress.aztec.formatting.n lineBlockFormatter = getLineBlockFormatter();
            lineBlockFormatter.getClass();
            Intrinsics.checkNotNullParameter(textFormat, "textFormat");
            String[] strArrSplit = TextUtils.split(lineBlockFormatter.u().toString(), "\n");
            ArrayList arrayList = new ArrayList();
            int length = strArrSplit.length;
            for (int i4 = 0; i4 < length; i4++) {
                kotlin.ranges.i it2 = new IntRange(0, i4 - 1, 1).iterator();
                int length2 = 0;
                while (it2.c) {
                    length2 += strArrSplit[it2.nextInt()].length() + 1;
                }
                int length3 = strArrSplit[i4].length() + length2;
                if (length2 < length3 && ((length2 >= i && i2 >= length3) || ((length2 <= i2 && i2 <= length3) || (length2 <= i && i <= length3)))) {
                    arrayList.add(Integer.valueOf(i4));
                }
            }
            if (!arrayList.isEmpty() && !arrayList.isEmpty()) {
                Iterator it3 = arrayList.iterator();
                while (it3.hasNext()) {
                    int iIntValue = ((Number) it3.next()).intValue();
                    String[] strArrSplit2 = TextUtils.split(lineBlockFormatter.u().toString(), "\n");
                    if (iIntValue >= 0 && iIntValue < strArrSplit2.length) {
                        kotlin.ranges.i it4 = new IntRange(0, iIntValue - 1, 1).iterator();
                        int length4 = 0;
                        while (it4.c) {
                            length4 += strArrSplit2[it4.nextInt()].length() + 1;
                        }
                        int length5 = strArrSplit2[iIntValue].length() + length4;
                        if (length4 >= length5) {
                            continue;
                        } else {
                            C5160h[] c5160hArr = (C5160h[]) lineBlockFormatter.u().getSpans(length4, length5, C5160h.class);
                            Intrinsics.d(c5160hArr);
                            if (c5160hArr.length > 0) {
                                C5160h c5160h = c5160hArr[0];
                                if (textFormat == x.b) {
                                    if (c5160h.k() == EnumC5157e.c) {
                                        return true;
                                    }
                                } else if (textFormat == x.c) {
                                    if (c5160h.k() == EnumC5157e.d) {
                                        return true;
                                    }
                                } else if (textFormat == x.d) {
                                    if (c5160h.k() == EnumC5157e.e) {
                                        return true;
                                    }
                                } else if (textFormat == x.e) {
                                    if (c5160h.k() == EnumC5157e.f) {
                                        return true;
                                    }
                                } else if (textFormat == x.f) {
                                    if (c5160h.k() == EnumC5157e.g) {
                                        return true;
                                    }
                                } else if (textFormat == x.g && c5160h.k() == EnumC5157e.h) {
                                    return true;
                                }
                            } else {
                                continue;
                            }
                        }
                    }
                }
            }
            return false;
        }
        if (textFormat == x.k || textFormat == x.l || textFormat == x.m || textFormat == x.n || textFormat == x.o || textFormat == x.p || textFormat == x.q || textFormat == x.G || textFormat == x.H || textFormat == x.I || textFormat == x.F) {
            return getInlineFormatter().W(i, i2, textFormat);
        }
        if (textFormat == x.h || textFormat == x.j || textFormat == x.i) {
            return getBlockFormatter().Z(i, i2, textFormat);
        }
        if (textFormat == x.r || textFormat == x.s || textFormat == x.t) {
            getBlockFormatter().getClass();
            Intrinsics.checkNotNullParameter(textFormat, "textFormat");
            return !r0.e0(i, i2, textFormat).isEmpty();
        }
        if (textFormat == x.u) {
            return getBlockFormatter().d0(getSelectionStart(), getSelectionEnd());
        }
        if (textFormat == x.y) {
            org.wordpress.aztec.formatting.i blockFormatter = getBlockFormatter();
            getSelectionStart();
            getSelectionEnd();
            return blockFormatter.c0();
        }
        if (textFormat == x.v) {
            org.wordpress.aztec.formatting.p linkFormatter = getLinkFormatter();
            linkFormatter.getClass();
            if (i <= i2) {
                if (i != i2) {
                    StringBuilder sb = new StringBuilder();
                    IntRange intRange = new IntRange(i, i2 - 1, 1);
                    ArrayList arrayList2 = new ArrayList();
                    kotlin.ranges.i it5 = intRange.iterator();
                    while (it5.c) {
                        Object next = it5.next();
                        int iIntValue2 = ((Number) next).intValue();
                        Object[] spans = linkFormatter.u().getSpans(iIntValue2, iIntValue2 + 1, AztecURLSpan.class);
                        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                        if (spans.length != 0) {
                            arrayList2.add(next);
                        }
                    }
                    Iterator it6 = arrayList2.iterator();
                    while (it6.hasNext()) {
                        int iIntValue3 = ((Number) it6.next()).intValue();
                        sb.append(linkFormatter.u().subSequence(iIntValue3, iIntValue3 + 1).toString());
                    }
                    return Intrinsics.b(linkFormatter.u().subSequence(i, i2).toString(), sb.toString());
                }
                int i5 = i - 1;
                if (i5 >= 0 && (i3 = i + 1) <= linkFormatter.u().length()) {
                    AztecURLSpan[] aztecURLSpanArr = (AztecURLSpan[]) linkFormatter.u().getSpans(i5, i, AztecURLSpan.class);
                    AztecURLSpan[] aztecURLSpanArr2 = (AztecURLSpan[]) linkFormatter.u().getSpans(i, i3, AztecURLSpan.class);
                    Intrinsics.d(aztecURLSpanArr);
                    if (aztecURLSpanArr.length != 0) {
                        Intrinsics.d(aztecURLSpanArr2);
                        if (aztecURLSpanArr2.length != 0) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public final void g(Editable editable, int i, int i2) {
        Intrinsics.checkNotNullParameter(editable, "editable");
        CharSequence charSequenceSubSequence = editable.subSequence(i, i2);
        com.google.android.gms.internal.appset.e eVar = new com.google.android.gms.internal.appset.e(this.A, this.W);
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(charSequenceSubSequence);
        e(spannableStringBuilder);
        com.google.android.gms.internal.appset.e.u(spannableStringBuilder);
        J2.c(spannableStringBuilder, this.y);
        Object[] spans = spannableStringBuilder.getSpans(0, spannableStringBuilder.length(), org.wordpress.aztec.spans.D.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        while (true) {
            boolean z = false;
            for (org.wordpress.aztec.spans.D d : CollectionsKt.g0(C4933y.K(spans, new com.google.zxing.aztec.encoder.c(27)))) {
                if (z) {
                    spannableStringBuilder.removeSpan(d);
                } else {
                    z = spannableStringBuilder.getSpanStart(d) == 0 && spannableStringBuilder.getSpanEnd(d) == spannableStringBuilder.length();
                    if (!z || !(d instanceof C5164l)) {
                    }
                }
            }
            String strD = J2.d(eVar.w(spannableStringBuilder), this.y, this.z);
            Object systemService = getContext().getSystemService("clipboard");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.content.ClipboardManager");
            ((ClipboardManager) systemService).setPrimaryClip(ClipData.newHtmlText("aztec", spannableStringBuilder.toString(), strD));
            return;
        }
    }

    @NotNull
    public final EnumC5145a getAlignmentRendering() {
        return this.A;
    }

    public final k getAztecKeyListener() {
        return null;
    }

    @NotNull
    public final org.wordpress.aztec.formatting.i getBlockFormatter() {
        org.wordpress.aztec.formatting.i iVar = this.L;
        if (iVar != null) {
            return iVar;
        }
        Intrinsics.m("blockFormatter");
        throw null;
    }

    public final boolean getCommentsVisible() {
        return this.x;
    }

    public final boolean getConsumeHistoryEvent() {
        return this.C;
    }

    @NotNull
    public final C5147c getContentChangeWatcher() {
        return this.m1;
    }

    public final int getDrawableFailed() {
        return this.G;
    }

    public final int getDrawableLoading() {
        return this.H;
    }

    public final org.wordpress.aztec.util.a getExternalLogger() {
        return null;
    }

    @Override // android.widget.EditText, android.widget.TextView
    public boolean getFreezesText() {
        return false;
    }

    @NotNull
    public final z getHistory() {
        z zVar = this.J;
        if (zVar != null) {
            return zVar;
        }
        Intrinsics.m("history");
        throw null;
    }

    public final B getImageGetter() {
        return null;
    }

    @NotNull
    public final byte[] getInitialEditorContentParsedSHA256() {
        return this.s;
    }

    @NotNull
    public final org.wordpress.aztec.formatting.l getInlineFormatter() {
        org.wordpress.aztec.formatting.l lVar = this.K;
        if (lVar != null) {
            return lVar;
        }
        Intrinsics.m("inlineFormatter");
        throw null;
    }

    public final int getLastPressedXCoord() {
        return this.n1;
    }

    public final int getLastPressedYCoord() {
        return this.o1;
    }

    @NotNull
    public final org.wordpress.aztec.formatting.n getLineBlockFormatter() {
        org.wordpress.aztec.formatting.n nVar = this.M;
        if (nVar != null) {
            return nVar;
        }
        Intrinsics.m("lineBlockFormatter");
        throw null;
    }

    @NotNull
    public final org.wordpress.aztec.formatting.p getLinkFormatter() {
        org.wordpress.aztec.formatting.p pVar = this.V;
        if (pVar != null) {
            return pVar;
        }
        Intrinsics.m("linkFormatter");
        throw null;
    }

    public final int getMaxImagesWidth() {
        return this.g1;
    }

    public final C getMediaCallback() {
        return null;
    }

    public final int getMinImagesWidth() {
        return this.h1;
    }

    @NotNull
    public final org.wordpress.aztec.watchers.event.sequence.a getObservationQueue() {
        return this.i1;
    }

    @NotNull
    public final ArrayList<Object> getPlugins() {
        return this.W;
    }

    @NotNull
    public final ArrayList<G> getSelectedStyles() {
        return this.F;
    }

    @NotNull
    public final String getSelectedText() {
        if (getSelectionStart() == -1 || getSelectionEnd() == -1 || getEditableText().length() < getSelectionEnd() || getEditableText().length() < getSelectionStart()) {
            return "";
        }
        Editable editableText = getEditableText();
        Intrinsics.checkNotNullExpressionValue(editableText, "getEditableText(...)");
        return editableText.subSequence(getSelectionStart(), getSelectionEnd()).toString();
    }

    @Override // android.widget.TextView
    public int getSelectionEnd() {
        return Math.max(super.getSelectionStart(), super.getSelectionEnd());
    }

    @Override // android.widget.TextView
    public int getSelectionStart() {
        return Math.min(super.getSelectionStart(), super.getSelectionEnd());
    }

    public final boolean getShouldAddMediaInline() {
        return this.B;
    }

    @NotNull
    public final org.wordpress.aztec.watchers.event.text.d getTextWatcherEventBuilder() {
        return this.j1;
    }

    public final org.wordpress.aztec.toolbar.a getToolbar() {
        return this.E;
    }

    public final int getVerticalHeadingMargin() {
        return this.f1;
    }

    public final int getVerticalParagraphMargin() {
        return this.e1;
    }

    public final int getVerticalParagraphPadding() {
        return this.d1;
    }

    public final D getVideoThumbnailGetter() {
        return null;
    }

    public final int getWidthMeasureSpec() {
        return this.c1;
    }

    public final void h() {
        org.wordpress.aztec.formatting.l inlineFormatter = getInlineFormatter();
        AztecText aztecText = (AztecText) inlineFormatter.b;
        int selectionStart = aztecText.getSelectionStart();
        int selectionEnd = aztecText.getSelectionEnd();
        char c = C2.i;
        if (selectionStart == 1 && selectionEnd == selectionStart) {
            Object[] spans = inlineFormatter.u().getSpans(0, 0, org.wordpress.aztec.spans.H.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            for (Object obj : spans) {
                org.wordpress.aztec.spans.H h = (org.wordpress.aztec.spans.H) obj;
                if (inlineFormatter.u().getSpanEnd(h) == selectionEnd && inlineFormatter.u().getSpanEnd(h) == selectionStart) {
                    inlineFormatter.u().removeSpan(h);
                }
            }
        } else if (aztecText.length() == 1 && aztecText.getText().charAt(0) == c) {
            Object[] spans2 = inlineFormatter.u().getSpans(0, 1, org.wordpress.aztec.spans.H.class);
            Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
            for (Object obj2 : spans2) {
                org.wordpress.aztec.spans.H h2 = (org.wordpress.aztec.spans.H) obj2;
                if (inlineFormatter.u().getSpanStart(h2) == 1 && inlineFormatter.u().getSpanEnd(h2) == 1) {
                    inlineFormatter.u().removeSpan(h2);
                }
            }
        }
        this.v = true;
        if (Intrinsics.b(getText().toString(), String.valueOf(c))) {
            this.m = true;
            getText().delete(0, 1);
            this.m = false;
        }
        onSelectionChanged(0, 0);
    }

    public final void i(String source, boolean z) {
        Intrinsics.checkNotNullParameter(source, "source");
        SpannableStringBuilder text = new SpannableStringBuilder();
        com.google.android.gms.internal.appset.e eVar = new com.google.android.gms.internal.appset.e(this.A, this.W);
        String strD = J2.d(org.wordpress.aztec.util.b.a(source), this.y, this.z);
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        text.append((CharSequence) eVar.n(context, strD));
        boolean z2 = this.y;
        Intrinsics.checkNotNullParameter(text, "text");
        if (z2) {
            Object[] spans = text.getSpans(0, text.length(), C5170s.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            for (Object obj : spans) {
                C5170s c5170s = (C5170s) obj;
                int spanStart = text.getSpanStart(c5170s);
                int spanEnd = text.getSpanEnd(c5170s);
                Object[] spans2 = text.getSpans(spanStart, spanEnd, T.class);
                Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
                if (spans2.length != 0) {
                    text.setSpan(new C5172u(0), spanEnd, spanEnd + 1, 33);
                }
            }
            Object[] spans3 = text.getSpans(0, text.length(), T.class);
            Intrinsics.checkNotNullExpressionValue(spans3, "getSpans(...)");
            ArrayList arrayList = new ArrayList();
            for (Object obj2 : spans3) {
                if (((T) obj2).b.getLength() == 0) {
                    arrayList.add(obj2);
                }
            }
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                text.removeSpan((T) it2.next());
            }
        }
        int length = text.length();
        Object[] spans4 = text.getSpans(0, length, org.wordpress.aztec.spans.D.class);
        Intrinsics.checkNotNullExpressionValue(spans4, "getSpans(...)");
        for (Object obj3 : spans4) {
            org.wordpress.aztec.spans.D blockElement = (org.wordpress.aztec.spans.D) obj3;
            org.wordpress.aztec.formatting.i blockFormatter = getBlockFormatter();
            Intrinsics.d(blockElement);
            blockFormatter.getClass();
            Intrinsics.checkNotNullParameter(blockElement, "blockElement");
            boolean z3 = blockElement instanceof AztecOrderedListSpan;
            org.wordpress.aztec.formatting.e eVar2 = blockFormatter.c;
            if (z3) {
                Intrinsics.checkNotNullParameter(eVar2, "<set-?>");
                ((AztecOrderedListSpan) blockElement).f = eVar2;
            } else if (blockElement instanceof AztecUnorderedListSpan) {
                Intrinsics.checkNotNullParameter(eVar2, "<set-?>");
                ((AztecUnorderedListSpan) blockElement).f = eVar2;
            } else if (blockElement instanceof AztecTaskListSpan) {
                Intrinsics.checkNotNullParameter(eVar2, "<set-?>");
                ((AztecTaskListSpan) blockElement).f = eVar2;
            } else if (blockElement instanceof C5168p) {
                org.wordpress.aztec.formatting.h hVar = blockFormatter.e;
                Intrinsics.checkNotNullParameter(hVar, "<set-?>");
                ((C5168p) blockElement).c = hVar;
            } else if (blockElement instanceof T) {
                org.wordpress.aztec.formatting.f fVar = blockFormatter.j;
                Intrinsics.checkNotNullParameter(fVar, "<set-?>");
                ((T) blockElement).c = fVar;
            } else if (blockElement instanceof AztecPreformatSpan) {
                ((AztecPreformatSpan) blockElement).w(blockFormatter.g);
            } else if (blockElement instanceof C5160h) {
                ((C5160h) blockElement).x(blockFormatter.f);
            }
        }
        Object[] spans5 = text.getSpans(0, length, C5172u.class);
        Intrinsics.checkNotNullExpressionValue(spans5, "getSpans(...)");
        for (Object obj4 : spans5) {
            ((C5172u) obj4).a = this.d1;
        }
        Object[] spans6 = text.getSpans(0, length, AztecURLSpan.class);
        Intrinsics.checkNotNullExpressionValue(spans6, "getSpans(...)");
        for (Object obj5 : spans6) {
            AztecURLSpan aztecURLSpan = (AztecURLSpan) obj5;
            org.wordpress.aztec.formatting.o oVar = getLinkFormatter().c;
            aztecURLSpan.getClass();
            Intrinsics.checkNotNullParameter(oVar, "<set-?>");
            aztecURLSpan.b = oVar;
        }
        Object[] spans7 = text.getSpans(0, length, C5154b.class);
        Intrinsics.checkNotNullExpressionValue(spans7, "getSpans(...)");
        for (Object obj6 : spans7) {
            C5154b c5154b = (C5154b) obj6;
            org.wordpress.aztec.formatting.j jVar = getInlineFormatter().c;
            c5154b.getClass();
            Intrinsics.checkNotNullParameter(jVar, "<set-?>");
            c5154b.c = jVar;
        }
        Object[] spans8 = text.getSpans(0, length, C5164l.class);
        Intrinsics.checkNotNullExpressionValue(spans8, "getSpans(...)");
        for (Object obj7 : spans8) {
            C5164l c5164l = (C5164l) obj7;
            org.wordpress.aztec.formatting.d dVar = this.p1;
            if (dVar == null) {
                Intrinsics.m("listItemStyle");
                throw null;
            }
            c5164l.getClass();
            Intrinsics.checkNotNullParameter(dVar, "<set-?>");
            c5164l.c = dVar;
        }
        C5163k[] c5163kArr = (C5163k[]) text.getSpans(0, length, C5163k.class);
        Intrinsics.d(c5163kArr);
        for (C5163k c5163k : c5163kArr) {
            c5163k.getClass();
            c5163k.f = new WeakReference(null);
        }
        org.wordpress.aztec.spans.r[] rVarArr = (org.wordpress.aztec.spans.r[]) text.getSpans(0, length, org.wordpress.aztec.spans.r.class);
        Intrinsics.d(rVarArr);
        for (org.wordpress.aztec.spans.r rVar : rVarArr) {
            rVar.getClass();
            rVar.f = new WeakReference(null);
        }
        C5153a[] c5153aArr = (C5153a[]) text.getSpans(0, length, C5153a.class);
        Intrinsics.d(c5153aArr);
        for (C5153a c5153a : c5153aArr) {
            c5153a.getClass();
            c5153a.f = new WeakReference(null);
        }
        X[] xArr = (X[]) text.getSpans(0, length, X.class);
        Intrinsics.d(xArr);
        for (X x : xArr) {
            x.c = this;
        }
        d(text, 0, length);
        if (!this.x) {
            C5171t[] c5171tArr = (C5171t[]) text.getSpans(0, length, C5171t.class);
            Intrinsics.d(c5171tArr);
            for (C5171t c5171t : c5171tArr) {
                Intrinsics.checkNotNullParameter(text, "spannable");
                c5171t.b = true;
                text.replace(text.getSpanStart(c5171t), text.getSpanEnd(c5171t), (CharSequence) C2.a);
            }
        }
        this.m = true;
        Object[] spans9 = text.getSpans(0, text.length(), AbstractC5156d.class);
        Intrinsics.checkNotNullExpressionValue(spans9, "getSpans(...)");
        for (Object obj8 : spans9) {
            ((AbstractC5156d) obj8).b = new WeakReference(this);
        }
        Intrinsics.checkNotNullParameter(text, "text");
        int iMin = Math.min(getSelectionStart(), text.length());
        Object[] spans10 = text.getSpans(0, text.length(), C5155c.class);
        Intrinsics.checkNotNullExpressionValue(spans10, "getSpans(...)");
        int length2 = spans10.length;
        int i = 0;
        while (i < length2) {
            C5155c c5155c = (C5155c) spans10[i];
            int spanStart2 = text.getSpanStart(c5155c);
            text.removeSpan(c5155c);
            i++;
            iMin = spanStart2;
        }
        int iMax = Math.max(0, Math.min(iMin, text.length()));
        setSelection(0);
        setTextKeepState(text);
        this.m = false;
        setSelection(iMax);
        if (z) {
            this.s = com.quizlet.quizletandroid.ui.profile.b.d(q(getText()), this.s);
        }
        C5163k[] c5163kArr2 = (C5163k[]) getText().getSpans(0, getText().length(), C5163k.class);
        Intrinsics.d(c5163kArr2);
        if (c5163kArr2.length != 0) {
            Context context2 = getContext();
            Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
            com.quizlet.quizletandroid.ui.profile.b.b(context2, this.H, this.g1);
            for (C5163k c5163k2 : c5163kArr2) {
            }
        }
        org.wordpress.aztec.spans.r[] rVarArr2 = (org.wordpress.aztec.spans.r[]) getText().getSpans(0, getText().length(), org.wordpress.aztec.spans.r.class);
        Intrinsics.d(rVarArr2);
        if (rVarArr2.length == 0) {
            return;
        }
        Context context3 = getContext();
        Intrinsics.checkNotNullExpressionValue(context3, "getContext(...)");
        com.quizlet.quizletandroid.ui.profile.b.b(context3, this.H, this.g1);
        for (org.wordpress.aztec.spans.r rVar2 : rVarArr2) {
        }
    }

    public final boolean j(KeyEvent keyEvent) {
        boolean z;
        if (keyEvent.getAction() == 0) {
            keyEvent.getKeyCode();
        }
        if (keyEvent.getAction() == 0) {
            keyEvent.getKeyCode();
        }
        if (keyEvent.getAction() != 0 || keyEvent.getKeyCode() != 67) {
            return false;
        }
        if (!this.C) {
            getHistory().a(this);
        }
        org.wordpress.aztec.formatting.i blockFormatter = getBlockFormatter();
        if (((AztecText) blockFormatter.b).getSelectionStart() != 0) {
            z = false;
        } else {
            Object[] spans = blockFormatter.u().getSpans(0, 0, org.wordpress.aztec.spans.D.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            int length = spans.length;
            int i = 0;
            z = false;
            while (i < length) {
                org.wordpress.aztec.spans.D d = (org.wordpress.aztec.spans.D) spans[i];
                int spanEnd = blockFormatter.u().getSpanEnd(d);
                int iL = StringsKt.L(blockFormatter.u(), '\n', 0, false, 6);
                if (iL == -1) {
                    iL = blockFormatter.u().length();
                }
                int i2 = iL + 1;
                if (spanEnd <= i2) {
                    blockFormatter.u().removeSpan(d);
                } else {
                    blockFormatter.u().setSpan(d, i2, spanEnd, blockFormatter.u().getSpanFlags(d));
                }
                i++;
                z = true;
            }
        }
        if (!this.B) {
            org.wordpress.aztec.formatting.i blockFormatter2 = getBlockFormatter();
            AztecText aztecText = (AztecText) blockFormatter2.b;
            if (aztecText.getSelectionStart() == aztecText.getSelectionEnd() && aztecText.getSelectionStart() > 0) {
                Object[] spans2 = blockFormatter2.u().getSpans(aztecText.getSelectionStart(), aztecText.getSelectionEnd(), AbstractC5167o.class);
                Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
                int length2 = spans2.length;
                int i3 = 0;
                while (true) {
                    if (i3 < length2) {
                        if (blockFormatter2.u().getSpanStart((AbstractC5167o) spans2[i3]) == aztecText.getSelectionStart()) {
                            break;
                        }
                        i3++;
                    } else {
                        Object[] spans3 = blockFormatter2.u().getSpans(aztecText.getSelectionStart(), aztecText.getSelectionEnd(), C5162j.class);
                        Intrinsics.checkNotNullExpressionValue(spans3, "getSpans(...)");
                        for (Object obj : spans3) {
                            if (blockFormatter2.u().getSpanStart((C5162j) obj) != aztecText.getSelectionStart()) {
                            }
                        }
                    }
                }
                aztecText.setSelection(aztecText.getSelectionStart() - 1);
            }
        }
        if (getSelectionStart() == 0 || getSelectionEnd() == 0) {
            h();
        }
        if (getText().length() == 0) {
            this.m = true;
            setText("");
            this.m = false;
        }
        this.m1.a();
        return z;
    }

    public final void k(AttributeSet attributeSet) throws Resources.NotFoundException {
        final int i = 0;
        this.m = true;
        TypedArray styles = getContext().obtainStyledAttributes(attributeSet, H.a, 0, R.style.AztecTextStyle);
        Intrinsics.checkNotNullExpressionValue(styles, "obtainStyledAttributes(...)");
        float dimension = styles.getDimension(29, getResources().getDimension(R.dimen.spacing_extra));
        String string = getResources().getString(R.dimen.spacing_multiplier);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        setLineSpacing(dimension, styles.getFloat(30, Float.parseFloat(string)));
        setBackgroundColor(styles.getColor(0, getContext().getColor(R.color.background)));
        setTextColor(styles.getColor(53, getContext().getColor(R.color.text)));
        setHintTextColor(styles.getColor(54, getContext().getColor(R.color.text_hint)));
        this.H = styles.getResourceId(11, R.drawable.ic_image_loading);
        this.G = styles.getResourceId(10, R.drawable.ic_image_failed);
        this.i = styles.getBoolean(27, this.i);
        this.j = styles.getInt(28, this.j);
        this.x = styles.getBoolean(9, this.x);
        this.d1 = styles.getDimensionPixelSize(1, getResources().getDimensionPixelSize(R.dimen.block_vertical_padding));
        this.e1 = styles.getDimensionPixelSize(33, getResources().getDimensionPixelSize(R.dimen.block_vertical_margin));
        this.f1 = styles.getDimensionPixelSize(25, getResources().getDimensionPixelSize(R.dimen.heading_vertical_padding));
        setInlineFormatter(new org.wordpress.aztec.formatting.l(this, new org.wordpress.aztec.formatting.j(styles.getColor(6, 0), styles.getFraction(7, 1, 1, DefinitionKt.NO_Float_VALUE), styles.getColor(8, 0)), new org.wordpress.aztec.formatting.k(styles.getResourceId(26, R.color.grey_lighten_10))));
        org.wordpress.aztec.formatting.e eVar = new org.wordpress.aztec.formatting.e(styles.getColor(2, 0), styles.getDimensionPixelSize(3, 0), styles.getDimensionPixelSize(4, 0), styles.getDimensionPixelSize(5, 0), this.d1);
        org.wordpress.aztec.formatting.d dVar = new org.wordpress.aztec.formatting.d(styles.getBoolean(52, false), styles.getColor(51, 0));
        this.p1 = dVar;
        org.wordpress.aztec.formatting.h hVar = new org.wordpress.aztec.formatting.h(styles.getColor(43, 0), styles.getColor(45, 0), styles.getColor(48, getContext().getColor(R.color.text)), styles.getFraction(44, 1, 1, DefinitionKt.NO_Float_VALUE), styles.getDimensionPixelSize(46, 0), styles.getDimensionPixelSize(47, 0), styles.getDimensionPixelSize(50, 0), styles.getDimensionPixelSize(49, this.d1));
        org.wordpress.aztec.formatting.c cVar = new org.wordpress.aztec.formatting.c(this.f1, V.f(new Pair(EnumC5157e.c, new org.wordpress.aztec.formatting.b(styles.getDimensionPixelSize(18, 0), styles.getColor(17, 0))), new Pair(EnumC5157e.d, new org.wordpress.aztec.formatting.b(styles.getDimensionPixelSize(24, 0), styles.getColor(23, 0))), new Pair(EnumC5157e.e, new org.wordpress.aztec.formatting.b(styles.getDimensionPixelSize(22, 0), styles.getColor(21, 0))), new Pair(EnumC5157e.f, new org.wordpress.aztec.formatting.b(styles.getDimensionPixelSize(16, 0), styles.getColor(15, 0))), new Pair(EnumC5157e.g, new org.wordpress.aztec.formatting.b(styles.getDimensionPixelSize(14, 0), styles.getColor(13, 0))), new Pair(EnumC5157e.h, new org.wordpress.aztec.formatting.b(styles.getDimensionPixelSize(20, 0), styles.getColor(19, 0)))));
        int color = styles.getColor(34, 0);
        Intrinsics.checkNotNullParameter(styles, "styles");
        setBlockFormatter(new org.wordpress.aztec.formatting.i(this, eVar, dVar, hVar, cVar, new org.wordpress.aztec.formatting.g(color, styles.getFraction(35, 1, 1, DefinitionKt.NO_Float_VALUE), styles.getColor(39, 0), styles.getDimensionPixelSize(42, this.d1), styles.getDimensionPixelSize(40, getResources().getDimensionPixelSize(R.dimen.preformat_leading_margin)), styles.getColor(36, 0), styles.getDimensionPixelSize(37, 0), styles.getDimensionPixelSize(38, 0), styles.getDimensionPixelSize(41, (int) getTextSize())), this.A, new org.wordpress.aztec.formatting.a(styles.getBoolean(12, false), this.d1), new org.wordpress.aztec.formatting.f(this.e1)));
        MovementMethod movementMethod = y.a;
        com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c cVar2 = new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(eVar);
        movementMethod.getClass();
        y.b = cVar2;
        setLinkFormatter(new org.wordpress.aztec.formatting.p(this, new org.wordpress.aztec.formatting.o(styles.getColor(31, 0), styles.getBoolean(32, true))));
        Intrinsics.checkNotNullParameter(this, "editor");
        setLineBlockFormatter(new org.wordpress.aztec.formatting.n(this));
        styles.recycle();
        this.g1 = Math.min(Math.min(getContext().getResources().getDisplayMetrics().widthPixels, getContext().getResources().getDisplayMetrics().heightPixels), 800);
        this.h1 = getLineHeight();
        boolean z = this.i;
        if (z && this.j <= 0) {
            throw new IllegalArgumentException("historySize must > 0");
        }
        setHistory(new z(z, this.j));
        setMovementMethod(movementMethod);
        setOnKeyListener(new com.onetrust.otpublishers.headless.UI.TVUI.adapter.m(this, 3));
        InputFilter inputFilter = new InputFilter(this) { // from class: org.wordpress.aztec.h
            public final /* synthetic */ AztecText b;

            {
                this.b = this;
            }

            @Override // android.text.InputFilter
            public final CharSequence filter(CharSequence charSequence, int i2, int i3, Spanned spanned, int i4, int i5) {
                AztecText this$0 = this.b;
                switch (i) {
                    case 0:
                        EnumC5145a enumC5145a = AztecText.q1;
                        Intrinsics.checkNotNullParameter(this$0, "this$0");
                        if (this$0.r || i5 >= spanned.length() || Intrinsics.b(charSequence, "\n")) {
                            return null;
                        }
                        C5163k[] c5163kArr = (C5163k[]) spanned.getSpans(i5, i5 + 1, C5163k.class);
                        Intrinsics.d(c5163kArr);
                        if (c5163kArr.length == 0) {
                            return null;
                        }
                        this$0.r = true;
                        this$0.q = true;
                        SpannableStringBuilder content = new SpannableStringBuilder(spanned.subSequence(0, i4)).append(charSequence.subSequence(i2, i3)).append(spanned.subSequence(i5, spanned.length()));
                        this$0.getHistory().a(this$0);
                        Intrinsics.d(content);
                        Intrinsics.checkNotNullParameter(content, "content");
                        Intrinsics.checkNotNullParameter(content, "content");
                        String strQ = this$0.q(content);
                        if (this$0.y) {
                            strQ = J2.b(strQ, true);
                        }
                        this$0.i(J2.b(strQ, this$0.y), false);
                        this$0.m1.a();
                        this$0.q = false;
                        this$0.r = false;
                        return null;
                    default:
                        EnumC5145a enumC5145a2 = AztecText.q1;
                        Intrinsics.checkNotNullParameter(this$0, "this$0");
                        if (this$0.getSelectionStart() == 0 && this$0.getSelectionEnd() == 0 && i2 == 0 && i4 == 0 && i5 == 0) {
                            Intrinsics.d(charSequence);
                            if (!this$0.z ? charSequence.length() == 0 : !(charSequence.length() != 1 || charSequence.charAt(0) != 8203)) {
                                if (!this$0.w) {
                                    this$0.w = true;
                                    this$0.C = true;
                                    this$0.j(new KeyEvent(0, 67));
                                    this$0.w = false;
                                }
                            }
                        }
                        return charSequence;
                }
            }
        };
        final int i2 = 1;
        InputFilter inputFilter2 = new InputFilter(this) { // from class: org.wordpress.aztec.h
            public final /* synthetic */ AztecText b;

            {
                this.b = this;
            }

            @Override // android.text.InputFilter
            public final CharSequence filter(CharSequence charSequence, int i22, int i3, Spanned spanned, int i4, int i5) {
                AztecText this$0 = this.b;
                switch (i2) {
                    case 0:
                        EnumC5145a enumC5145a = AztecText.q1;
                        Intrinsics.checkNotNullParameter(this$0, "this$0");
                        if (this$0.r || i5 >= spanned.length() || Intrinsics.b(charSequence, "\n")) {
                            return null;
                        }
                        C5163k[] c5163kArr = (C5163k[]) spanned.getSpans(i5, i5 + 1, C5163k.class);
                        Intrinsics.d(c5163kArr);
                        if (c5163kArr.length == 0) {
                            return null;
                        }
                        this$0.r = true;
                        this$0.q = true;
                        SpannableStringBuilder content = new SpannableStringBuilder(spanned.subSequence(0, i4)).append(charSequence.subSequence(i22, i3)).append(spanned.subSequence(i5, spanned.length()));
                        this$0.getHistory().a(this$0);
                        Intrinsics.d(content);
                        Intrinsics.checkNotNullParameter(content, "content");
                        Intrinsics.checkNotNullParameter(content, "content");
                        String strQ = this$0.q(content);
                        if (this$0.y) {
                            strQ = J2.b(strQ, true);
                        }
                        this$0.i(J2.b(strQ, this$0.y), false);
                        this$0.m1.a();
                        this$0.q = false;
                        this$0.r = false;
                        return null;
                    default:
                        EnumC5145a enumC5145a2 = AztecText.q1;
                        Intrinsics.checkNotNullParameter(this$0, "this$0");
                        if (this$0.getSelectionStart() == 0 && this$0.getSelectionEnd() == 0 && i22 == 0 && i4 == 0 && i5 == 0) {
                            Intrinsics.d(charSequence);
                            if (!this$0.z ? charSequence.length() == 0 : !(charSequence.length() != 1 || charSequence.charAt(0) != 8203)) {
                                if (!this$0.w) {
                                    this$0.w = true;
                                    this$0.C = true;
                                    this$0.j(new KeyEvent(0, 67));
                                    this$0.w = false;
                                }
                            }
                        }
                        return charSequence;
                }
            }
        };
        int i3 = Build.VERSION.SDK_INT;
        if (i3 == 26 || i3 == 27) {
            setFilters(new InputFilter[]{inputFilter, inputFilter2});
        } else {
            setFilters(new InputFilter[]{inputFilter2});
        }
        Intrinsics.checkNotNullParameter(this, "text");
        addTextChangedListener(new org.wordpress.aztec.watchers.d(this, 0));
        Intrinsics.checkNotNullParameter(this, "text");
        addTextChangedListener(new org.wordpress.aztec.watchers.e());
        int i4 = this.d1;
        Intrinsics.checkNotNullParameter(this, "editText");
        addTextChangedListener(new com.google.android.material.textfield.u(this, i4));
        Intrinsics.checkNotNullParameter(this, "text");
        addTextChangedListener(new org.wordpress.aztec.watchers.g(this));
        org.wordpress.aztec.formatting.l inlineFormatter = getInlineFormatter();
        Intrinsics.checkNotNullParameter(inlineFormatter, "inlineFormatter");
        Intrinsics.checkNotNullParameter(this, "text");
        addTextChangedListener(new com.quizlet.edgy.utils.d(inlineFormatter, this));
        com.quizlet.edgy.utils.d dVar2 = new com.quizlet.edgy.utils.d(this);
        EnumC5145a enumC5145a = this.A;
        dVar2.a(new org.wordpress.aztec.handlers.c(enumC5145a));
        Intrinsics.checkNotNullParameter(AztecListSpan.class, "clazz");
        dVar2.a(new org.wordpress.aztec.handlers.d(AztecListSpan.class, i));
        org.wordpress.aztec.formatting.d dVar3 = this.p1;
        if (dVar3 == null) {
            Intrinsics.m("listItemStyle");
            throw null;
        }
        dVar2.a(new org.wordpress.aztec.handlers.e(enumC5145a, dVar3));
        Intrinsics.checkNotNullParameter(C5168p.class, "clazz");
        dVar2.a(new org.wordpress.aztec.handlers.d(C5168p.class, 2));
        Intrinsics.checkNotNullParameter(AztecPreformatSpan.class, "clazz");
        dVar2.a(new org.wordpress.aztec.handlers.d(AztecPreformatSpan.class, 1));
        Intrinsics.checkNotNullParameter(this, "text");
        addTextChangedListener(dVar2);
        Intrinsics.checkNotNullParameter(this, "text");
        addTextChangedListener(new org.wordpress.aztec.watchers.d(this, 2));
        Intrinsics.checkNotNullParameter(this, "text");
        addTextChangedListener(new org.wordpress.aztec.watchers.c(this));
        Intrinsics.checkNotNullParameter(this, "editText");
        Editable text = getText();
        Intrinsics.checkNotNullParameter(text, "text");
        TextWatcher bVar = new org.wordpress.aztec.watchers.b();
        Y2.a(text, false);
        addTextChangedListener(bVar);
        Intrinsics.checkNotNullParameter(this, "editText");
        addTextChangedListener(new C4197k(this));
        Intrinsics.checkNotNullParameter(this, "text");
        addTextChangedListener(new org.wordpress.aztec.watchers.a(this));
        addTextChangedListener(new U0(this, 5));
        Intrinsics.checkNotNullParameter(this, "text");
        addTextChangedListener(new org.wordpress.aztec.watchers.d(this, 1));
        addTextChangedListener(this);
        setSelection(0);
        if (i3 >= 28) {
            setOnLongClickListener(new com.quizlet.quizletandroid.ui.common.adapter.ndl.a(this));
        }
        this.m = false;
        this.u = true;
    }

    public final boolean l() {
        return this.i1.c.size() > 0 && !this.p && r1 == 1;
    }

    public final String m(Editable editable) throws Exception {
        com.google.android.gms.internal.appset.e eVar = new com.google.android.gms.internal.appset.e(this.A, this.W);
        try {
            SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(editable);
            e(spannableStringBuilder);
            Object[] spans = spannableStringBuilder.getSpans(0, spannableStringBuilder.length(), C5155c.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            for (C5155c c5155c : (C5155c[]) spans) {
                spannableStringBuilder.removeSpan(c5155c);
            }
            com.google.android.gms.internal.appset.e.u(spannableStringBuilder);
            J2.c(spannableStringBuilder, this.y);
            String string = eVar.w(spannableStringBuilder);
            Intrinsics.checkNotNullParameter(string, "string");
            if (string.length() > 0 && string.charAt(string.length() - 1) == C2.i) {
                string.subSequence(0, string.length() - 2).toString();
            }
            return string;
        } catch (Exception e) {
            org.wordpress.android.util.a.b("There was an error creating SpannableStringBuilder. See #452 and #582 for details.");
            throw e;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x00a5  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00d5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void n(android.text.Editable r17, int r18, int r19, boolean r20) {
        /*
            Method dump skipped, instructions count: 512
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.wordpress.aztec.AztecText.n(android.text.Editable, int, int, boolean):void");
    }

    public final void o() {
        Pair pairU = getLinkFormatter().U();
        org.wordpress.aztec.formatting.p linkFormatter = getLinkFormatter();
        Object obj = pairU.a;
        int iIntValue = ((Number) obj).intValue();
        Object obj2 = pairU.b;
        linkFormatter.W(iIntValue, ((Number) obj2).intValue());
        onSelectionChanged(((Number) obj).intValue(), ((Number) obj2).intValue());
    }

    @Override // androidx.appcompat.widget.C0116w, android.widget.TextView, android.view.View
    public final InputConnection onCreateInputConnection(EditorInfo outAttrs) {
        Intrinsics.checkNotNullParameter(outAttrs, "outAttrs");
        InputConnection inputConnectionOnCreateInputConnection = super.onCreateInputConnection(outAttrs);
        if (inputConnectionOnCreateInputConnection == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        androidx.core.view.inputmethod.b bVar = new androidx.core.view.inputmethod.b((androidx.emoji2.viewsintegration.b) inputConnectionOnCreateInputConnection, new C0981a(this, 10));
        String string = Settings.Secure.getString(getContext().getContentResolver(), "default_input_method");
        String MANUFACTURER = Build.MANUFACTURER;
        Intrinsics.checkNotNullExpressionValue(MANUFACTURER, "MANUFACTURER");
        Locale locale = Locale.US;
        if (Intrinsics.b(androidx.compose.ui.node.B.k(locale, "US", MANUFACTURER, locale, "toLowerCase(...)"), "samsung") && Build.VERSION.SDK_INT >= 33 && string != null) {
            kotlin.text.D.r(string, "com.samsung.android.honeyboard", false);
        }
        return bVar;
    }

    @Override // androidx.appcompat.widget.C0116w, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        removeTextChangedListener(this);
        DialogInterfaceC0052h dialogInterfaceC0052h = this.k;
        if (dialogInterfaceC0052h != null && dialogInterfaceC0052h.isShowing()) {
            DialogInterfaceC0052h dialogInterfaceC0052h2 = this.k;
            Intrinsics.d(dialogInterfaceC0052h2);
            dialogInterfaceC0052h2.dismiss();
        }
        DialogInterfaceC0052h dialogInterfaceC0052h3 = this.l;
        if (dialogInterfaceC0052h3 != null && dialogInterfaceC0052h3.isShowing()) {
            DialogInterfaceC0052h dialogInterfaceC0052h4 = this.l;
            Intrinsics.d(dialogInterfaceC0052h4);
            dialogInterfaceC0052h4.dismiss();
        }
        y.a.getClass();
        y.c = new WeakReference(null);
        AztecTaskListSpan[] aztecTaskListSpanArr = (AztecTaskListSpan[]) getEditableText().getSpans(0, getEditableText().length(), AztecTaskListSpan.class);
        Intrinsics.d(aztecTaskListSpanArr);
        for (AztecTaskListSpan aztecTaskListSpan : aztecTaskListSpanArr) {
            aztecTaskListSpan.g = null;
        }
    }

    @Override // android.widget.TextView, android.view.View
    public final void onDraw(Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        ArrayList arrayList = this.W;
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            it2.next();
        }
        Iterator it3 = arrayList2.iterator();
        if (it3.hasNext()) {
            throw android.support.v4.media.session.a.d(it3);
        }
        super.onDraw(canvas);
    }

    @Override // android.widget.TextView, android.view.View
    public final boolean onKeyPreIme(int i, KeyEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (event.getKeyCode() == 4) {
            event.getAction();
        }
        return super.onKeyPreIme(i, event);
    }

    @Override // android.widget.TextView, android.view.View, android.view.KeyEvent.Callback
    public final boolean onKeyUp(int i, KeyEvent keyEvent) {
        Intrinsics.checkNotNullParameter(keyEvent, "keyEvent");
        org.wordpress.aztec.toolbar.a aVar = this.E;
        if (aVar != null ? aVar.onKeyUp(i, keyEvent) : false) {
            return true;
        }
        return super.onKeyUp(i, keyEvent);
    }

    @Override // android.widget.TextView, android.view.View
    public final void onMeasure(int i, int i2) {
        this.c1 = i;
        super.onMeasure(i, i2);
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x00e4  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x011e  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0129  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x012b  */
    @Override // android.widget.TextView, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onRestoreInstanceState(android.os.Parcelable r15) {
        /*
            Method dump skipped, instructions count: 656
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.wordpress.aztec.AztecText.onRestoreInstanceState(android.os.Parcelable):void");
    }

    @Override // android.widget.TextView, android.view.View
    public final Parcelable onSaveInstanceState() throws IOException {
        SavedState savedState;
        Editable text;
        Editable text2;
        Parcelable superState = super.onSaveInstanceState();
        if (superState != null) {
            Intrinsics.checkNotNullParameter(superState, "superState");
            savedState = new SavedState(superState);
            savedState.a = new Bundle();
        } else {
            savedState = null;
        }
        Bundle bundle = new Bundle();
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        org.wordpress.aztec.util.b.h(context, "HISTORY_LIST_KEY", new ArrayList(getHistory().d), bundle);
        bundle.putInt("HISTORY_CURSOR_KEY", getHistory().c);
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        org.wordpress.aztec.util.b.h(context2, "INPUT_LAST_KEY", getHistory().e, bundle);
        bundle.putInt("VISIBILITY_KEY", getVisibility());
        bundle.putByteArray("RETAINED_INITIAL_HTML_PARSED_SHA256_KEY", this.s);
        Context context3 = getContext();
        Intrinsics.checkNotNullExpressionValue(context3, "getContext(...)");
        Editable content = getText();
        Intrinsics.checkNotNullParameter(content, "content");
        String strQ = q(content);
        if (this.y) {
            strQ = J2.b(strQ, true);
        }
        org.wordpress.aztec.util.b.h(context3, "RETAINED_HTML_KEY", strQ, bundle);
        bundle.putInt("SELECTION_START_KEY", getSelectionStart());
        bundle.putInt("SELECTION_END_KEY", getSelectionEnd());
        DialogInterfaceC0052h dialogInterfaceC0052h = this.k;
        if (dialogInterfaceC0052h != null && dialogInterfaceC0052h.isShowing()) {
            bundle.putBoolean("LINK_DIALOG_VISIBLE_KEY", true);
            DialogInterfaceC0052h dialogInterfaceC0052h2 = this.k;
            Intrinsics.d(dialogInterfaceC0052h2);
            EditText editText = (EditText) dialogInterfaceC0052h2.findViewById(R.id.linkURL);
            DialogInterfaceC0052h dialogInterfaceC0052h3 = this.k;
            Intrinsics.d(dialogInterfaceC0052h3);
            EditText editText2 = (EditText) dialogInterfaceC0052h3.findViewById(R.id.linkText);
            DialogInterfaceC0052h dialogInterfaceC0052h4 = this.k;
            Intrinsics.d(dialogInterfaceC0052h4);
            CheckBox checkBox = (CheckBox) dialogInterfaceC0052h4.findViewById(R.id.openInNewWindow);
            bundle.putString("LINK_DIALOG_URL_KEY", (editText == null || (text2 = editText.getText()) == null) ? null : text2.toString());
            bundle.putString("LINK_DIALOG_ANCHOR_KEY", (editText2 == null || (text = editText2.getText()) == null) ? null : text.toString());
            bundle.putString("LINK_DIALOG_OPEN_NEW_WINDOW_KEY", (checkBox == null || !checkBox.isChecked()) ? "checked=false" : "checked=true");
        }
        DialogInterfaceC0052h dialogInterfaceC0052h5 = this.l;
        if (dialogInterfaceC0052h5 != null && dialogInterfaceC0052h5.isShowing()) {
            DialogInterfaceC0052h dialogInterfaceC0052h6 = this.l;
            Intrinsics.d(dialogInterfaceC0052h6);
            SourceViewEditText sourceViewEditText = (SourceViewEditText) dialogInterfaceC0052h6.findViewById(R.id.source);
            bundle.putBoolean("BLOCK_DIALOG_VISIBLE_KEY", true);
            bundle.putInt("BLOCK_EDITOR_START_INDEX_KEY", this.D);
            Context context4 = getContext();
            Intrinsics.checkNotNullExpressionValue(context4, "getContext(...)");
            org.wordpress.aztec.util.b.h(context4, "RETAINED_BLOCK_HTML_KEY", sourceViewEditText != null ? sourceViewEditText.b() : null, bundle);
        }
        bundle.putBoolean("IS_MEDIA_ADDED_KEY", this.I);
        if (savedState == null) {
            return savedState;
        }
        Intrinsics.checkNotNullParameter(bundle, "<set-?>");
        savedState.a = bundle;
        return savedState;
    }

    @Override // android.widget.TextView
    public final void onSelectionChanged(int i, int i2) {
        super.onSelectionChanged(i, i2);
        if (this.u) {
            if (this.n) {
                if (this.z) {
                    return;
                }
                this.n = false;
                return;
            }
            int length = length();
            char c = C2.i;
            if (length != 0 && ((i == length() || i2 == length()) && getText().charAt(length() - 1) == c)) {
                if (i == length()) {
                    i--;
                }
                if (i2 == length()) {
                    i2--;
                }
                setSelection(i, i2);
                return;
            }
            if (!this.v && length() == 1 && getText().charAt(0) == c) {
                return;
            }
            p pVar = this.t;
            if (pVar != null) {
                ((QRichTextToolbar) pVar).c(i, i2);
            }
            if (!this.z) {
                ArrayList<G> arrayList = new ArrayList<>();
                if (i >= 0 && i2 >= 0) {
                    int i3 = i > i2 ? i2 : i;
                    Editable editableText = getEditableText();
                    Intrinsics.checkNotNullExpressionValue(editableText, "getEditableText(...)");
                    if (editableText.length() != 0) {
                        if ((i3 == 0 && i2 == 0) || (i3 == i2 && getEditableText().length() > i && getEditableText().charAt(i - 1) == C2.g)) {
                            i2++;
                        } else if (i3 > 0 && getSelectionStart() == getSelectionEnd()) {
                            i3--;
                        }
                        for (x xVar : x.values()) {
                            if (f(i3, i2, xVar)) {
                                arrayList.add(xVar);
                            }
                        }
                        ArrayList arrayList2 = this.W;
                        ArrayList arrayList3 = new ArrayList();
                        Iterator it2 = arrayList2.iterator();
                        while (it2.hasNext()) {
                            if (it2.next() != null) {
                                throw new ClassCastException();
                            }
                        }
                        ArrayList arrayList4 = new ArrayList();
                        Iterator it3 = arrayList3.iterator();
                        if (it3.hasNext()) {
                            if (it3.next() != null) {
                                throw new ClassCastException();
                            }
                            Intrinsics.e(null, "null cannot be cast to non-null type org.wordpress.aztec.plugins.IToolbarButton");
                            throw null;
                        }
                        Iterator it4 = arrayList4.iterator();
                        while (it4.hasNext()) {
                            G g = (G) it4.next();
                            if (f(i3, i2, g)) {
                                arrayList.add(g);
                            }
                        }
                    }
                }
                setSelectedStyles(arrayList);
            }
            this.v = false;
        }
    }

    @Override // android.widget.TextView, android.text.TextWatcher
    public final void onTextChanged(CharSequence text, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(text, "text");
        if (this.u && l()) {
            org.wordpress.aztec.watchers.event.text.c cVar = new org.wordpress.aztec.watchers.event.text.c(new SpannableStringBuilder(text), i, i2, i3);
            org.wordpress.aztec.watchers.event.text.d dVar = this.j1;
            dVar.getClass();
            Intrinsics.checkNotNullParameter(cVar, "<set-?>");
            dVar.b = cVar;
        }
    }

    @Override // androidx.appcompat.widget.C0116w, android.widget.EditText, android.widget.TextView
    public final boolean onTextContextMenuItem(int i) {
        int iMax;
        int iMax2;
        int length = getText().length();
        if (isFocused()) {
            iMax2 = Math.max(0, Math.min(getSelectionStart(), getSelectionEnd()));
            iMax = Math.max(0, Math.max(getSelectionStart(), getSelectionEnd()));
        } else {
            iMax = length;
            iMax2 = 0;
        }
        int identifier = getResources().getIdentifier("android:id/clipboard", "id", getContext().getPackageName());
        if (i == 16908322) {
            n(getText(), iMax2, iMax, false);
            return true;
        }
        if (i == 16908337) {
            n(getText(), iMax2, iMax, true);
            return true;
        }
        if (i == 16908321) {
            g(getText(), iMax2, iMax);
            setSelection(iMax);
            return true;
        }
        if (i == 16908320) {
            g(getText(), iMax2, iMax);
            getText().delete(iMax2, iMax);
            if (iMax2 == 0) {
                h();
            }
            return true;
        }
        if (i != identifier) {
            if (i == 16908319 && Intrinsics.b(getText().toString(), String.valueOf(C2.i))) {
                h();
                return true;
            }
            return super.onTextContextMenuItem(i);
        }
        if (Build.VERSION.SDK_INT < 28) {
            String MANUFACTURER = Build.MANUFACTURER;
            Intrinsics.checkNotNullExpressionValue(MANUFACTURER, "MANUFACTURER");
            Locale locale = Locale.getDefault();
            Intrinsics.checkNotNullExpressionValue(locale, "getDefault(...)");
            String lowerCase = MANUFACTURER.toLowerCase(locale);
            Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
            if (lowerCase.equals("samsung")) {
                Toast.makeText(getContext(), getContext().getString(R.string.samsung_disabled_custom_clipboard, Build.VERSION.RELEASE), 1).show();
                return true;
            }
        }
        return super.onTextContextMenuItem(i);
    }

    @Override // android.widget.TextView, android.view.View
    public final boolean onTouchEvent(MotionEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (Build.VERSION.SDK_INT >= 28 && event.getAction() == 0) {
            this.n1 = (int) event.getRawX();
            this.o1 = (int) event.getRawY();
        }
        return super.onTouchEvent(event);
    }

    @Override // android.widget.TextView, android.view.View
    public final void onWindowFocusChanged(boolean z) {
        int selectionStart = getSelectionStart();
        int selectionEnd = getSelectionEnd();
        super.onWindowFocusChanged(z);
        if (z) {
            return;
        }
        setSelection(selectionStart, selectionEnd);
    }

    public final void p(final X unknownHtmlSpan, String source) {
        Intrinsics.checkNotNullParameter(unknownHtmlSpan, "unknownHtmlSpan");
        Intrinsics.checkNotNullParameter(source, "html");
        C0051g c0051g = new C0051g(getContext(), R.style.ResizableDialogTheme);
        View viewInflate = LayoutInflater.from(getContext()).inflate(R.layout.dialog_block_editor, (ViewGroup) null);
        final SourceViewEditText sourceViewEditText = (SourceViewEditText) viewInflate.findViewById(R.id.source);
        if (TextUtils.isEmpty(source)) {
            source = unknownHtmlSpan.b.toString();
            Intrinsics.checkNotNullExpressionValue(source, "toString(...)");
        }
        sourceViewEditText.getClass();
        Intrinsics.checkNotNullParameter(source, "source");
        SpannableStringBuilder styledHtml = new SpannableStringBuilder(J2.b(source, sourceViewEditText.j));
        int i = sourceViewEditText.g;
        int i2 = sourceViewEditText.h;
        Intrinsics.checkNotNullParameter(styledHtml, "content");
        K2.d(styledHtml, 0, styledHtml.length(), i, i2);
        sourceViewEditText.l = true;
        Intrinsics.checkNotNullParameter(styledHtml, "styledHtml");
        int iM = StringsKt.M(styledHtml, "aztec_cursor", 0, false, 6);
        if (iM < 0) {
            iM = 0;
        } else {
            boolean z = iM > 0 && styledHtml.charAt(iM + (-1)) == '\n';
            int i3 = iM + 12;
            boolean z2 = iM + 13 < styledHtml.length() && styledHtml.charAt(i3) == '\n';
            styledHtml.delete(iM, i3);
            if (z && z2) {
                int i4 = iM - 1;
                styledHtml.delete(i4, iM);
                iM = i4;
            }
            new Regex("aztec_cursor").replace(styledHtml, "");
        }
        sourceViewEditText.setText(styledHtml);
        sourceViewEditText.n = com.quizlet.quizletandroid.ui.profile.b.d(sourceViewEditText.b(), sourceViewEditText.n);
        sourceViewEditText.l = false;
        if (iM > 0) {
            sourceViewEditText.setSelection(iM);
        }
        c0051g.setView(viewInflate);
        c0051g.setPositiveButton(R.string.block_editor_dialog_button_save, new DialogInterface.OnClickListener() { // from class: org.wordpress.aztec.g
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i5) {
                EnumC5145a enumC5145a = AztecText.q1;
                AztecText this$0 = this.a;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                X unknownHtmlSpan2 = unknownHtmlSpan;
                Intrinsics.checkNotNullParameter(unknownHtmlSpan2, "$unknownHtmlSpan");
                int spanStart = this$0.getText().getSpanStart(unknownHtmlSpan2);
                SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder();
                com.google.android.gms.internal.appset.e eVar = new com.google.android.gms.internal.appset.e(this$0.A, this$0.W);
                String strB = sourceViewEditText.b();
                Context context = this$0.getContext();
                Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                spannableStringBuilder.append(StringsKt.g0(eVar.n(context, strB)));
                this$0.setSelection(spanStart);
                this$0.m = true;
                this$0.getText().removeSpan(unknownHtmlSpan2);
                int i6 = 1 + spanStart;
                Object[] spans = this$0.getText().getSpans(spanStart, i6, org.wordpress.aztec.spans.V.class);
                Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                org.wordpress.aztec.spans.V v = (org.wordpress.aztec.spans.V) C4933y.B(spans);
                if (v != null) {
                    this$0.getText().removeSpan(v);
                }
                this$0.getText().replace(spanStart, i6, spannableStringBuilder);
                Object[] spans2 = spannableStringBuilder.getSpans(0, spannableStringBuilder.length(), X.class);
                Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
                X x = (X) C4933y.B(spans2);
                if (x != null) {
                    x.c = this$0;
                }
                this$0.m = false;
                this$0.getInlineFormatter().Y(0, this$0.getText().length());
            }
        });
        c0051g.setNegativeButton(R.string.block_editor_dialog_button_cancel, new com.quizlet.quizletandroid.ui.login.B(2));
        this.D = getText().getSpanStart(unknownHtmlSpan);
        DialogInterfaceC0052h dialogInterfaceC0052hCreate = c0051g.create();
        this.l = dialogInterfaceC0052hCreate;
        if (dialogInterfaceC0052hCreate != null) {
            dialogInterfaceC0052hCreate.show();
        }
    }

    public final String q(Editable content) {
        Intrinsics.checkNotNullParameter(content, "content");
        if (Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
            return m(content);
        }
        return (String) kotlinx.coroutines.E.D(kotlin.coroutines.n.a, new w(this, content, null));
    }

    public final void setAztecKeyListener(@NotNull k listenerAztec) {
        Intrinsics.checkNotNullParameter(listenerAztec, "listenerAztec");
    }

    public final void setBackgroundSpanColor(int i) {
        getInlineFormatter().e = Integer.valueOf(i);
    }

    public final void setBeforeBackSpaceListener(@NotNull i listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    public final void setBlockFormatter(@NotNull org.wordpress.aztec.formatting.i iVar) {
        Intrinsics.checkNotNullParameter(iVar, "<set-?>");
        this.L = iVar;
    }

    public final void setCalypsoMode(boolean z) {
        this.y = z;
    }

    public final void setCommentsVisible(boolean z) {
        this.x = z;
    }

    public final void setConsumeHistoryEvent(boolean z) {
        this.C = z;
    }

    public final void setDrawableFailed(int i) {
        this.G = i;
    }

    public final void setDrawableLoading(int i) {
        this.H = i;
    }

    public final void setExternalLogger(org.wordpress.aztec.util.a aVar) {
    }

    public final void setFocusOnVisible(boolean z) {
        this.l1 = z;
    }

    public final void setGutenbergMode(boolean z) {
        this.z = z;
    }

    public final void setHistory(@NotNull z zVar) {
        Intrinsics.checkNotNullParameter(zVar, "<set-?>");
        this.J = zVar;
    }

    public final void setImageGetter(B b) {
    }

    public final void setInCalypsoMode(boolean z) {
        this.y = z;
    }

    public final void setInGutenbergMode(boolean z) {
        this.z = z;
    }

    public final void setInitialEditorContentParsedSHA256(@NotNull byte[] bArr) {
        Intrinsics.checkNotNullParameter(bArr, "<set-?>");
        this.s = bArr;
    }

    public final void setInlineFormatter(@NotNull org.wordpress.aztec.formatting.l lVar) {
        Intrinsics.checkNotNullParameter(lVar, "<set-?>");
        this.K = lVar;
    }

    public final void setLastPressedXCoord(int i) {
        this.n1 = i;
    }

    public final void setLastPressedYCoord(int i) {
        this.o1 = i;
    }

    public final void setLineBlockFormatter(@NotNull org.wordpress.aztec.formatting.n nVar) {
        Intrinsics.checkNotNullParameter(nVar, "<set-?>");
        this.M = nVar;
    }

    public final void setLinkFormatter(@NotNull org.wordpress.aztec.formatting.p pVar) {
        Intrinsics.checkNotNullParameter(pVar, "<set-?>");
        this.V = pVar;
    }

    public final void setLinkTapEnabled(boolean z) {
        y.a.getClass();
        y.d = z;
    }

    public final void setMaxImagesWidth(int i) {
        this.g1 = i;
    }

    public final void setMediaAdded(boolean z) {
        this.I = z;
    }

    public final void setMediaCallback(C c) {
    }

    public final void setMinImagesWidth(int i) {
        this.h1 = i;
    }

    public final void setObservationQueue(@NotNull org.wordpress.aztec.watchers.event.sequence.a aVar) {
        Intrinsics.checkNotNullParameter(aVar, "<set-?>");
        this.i1 = aVar;
    }

    public final void setOnAudioTappedListener(@NotNull j listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    public final void setOnImageTappedListener(@NotNull l listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    public final void setOnImeBackListener(@NotNull m listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    public final void setOnLinkTappedListener(@NotNull n listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        y.a.getClass();
        y.c = new WeakReference(null);
    }

    public final void setOnMediaDeletedListener(@NotNull o listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    public final void setOnSelectionChangedListener(@NotNull p onSelectionChangedListener) {
        Intrinsics.checkNotNullParameter(onSelectionChangedListener, "onSelectionChangedListener");
        this.t = onSelectionChangedListener;
    }

    public final void setOnVideoInfoRequestedListener(@NotNull q listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    public final void setOnVideoTappedListener(@NotNull r listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    public final void setOnVisibilityChangeListener(@NotNull s listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    public final void setPlugins(@NotNull ArrayList<Object> arrayList) {
        Intrinsics.checkNotNullParameter(arrayList, "<set-?>");
        this.W = arrayList;
    }

    public final void setSelectedStyles(@NotNull ArrayList<G> styles) {
        Intrinsics.checkNotNullParameter(styles, "styles");
        ArrayList arrayList = this.F;
        arrayList.clear();
        arrayList.addAll(styles);
    }

    public final void setShouldAddMediaInline(boolean z) {
        this.B = z;
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.Map] */
    public final void setTextSizeModifier(int i) {
        org.wordpress.aztec.formatting.i blockFormatter = getBlockFormatter();
        Iterator it2 = blockFormatter.f.b.entrySet().iterator();
        while (it2.hasNext()) {
            ((org.wordpress.aztec.formatting.b) ((Map.Entry) it2.next()).getValue()).b = i;
        }
        blockFormatter.g.i += i;
        float f = i;
        if (getTextSize() + f >= DefinitionKt.NO_Float_VALUE) {
            setTextSize(0, getTextSize() + f);
        } else {
            setTextSize(0, DefinitionKt.NO_Float_VALUE);
        }
    }

    public final void setTextWatcherEventBuilder(@NotNull org.wordpress.aztec.watchers.event.text.d dVar) {
        Intrinsics.checkNotNullParameter(dVar, "<set-?>");
        this.j1 = dVar;
    }

    public final void setToolbar(org.wordpress.aztec.toolbar.a aVar) {
        this.E = aVar;
    }

    public final void setVerticalHeadingMargin(int i) {
        this.f1 = i;
    }

    public final void setVerticalParagraphMargin(int i) {
        this.e1 = i;
    }

    public final void setVerticalParagraphPadding(int i) {
        this.d1 = i;
    }

    public final void setVideoThumbnailGetter(D d) {
    }

    @Override // android.view.View
    public void setVisibility(int i) {
        super.setVisibility(i);
        if (i == 0 && this.l1) {
            requestFocus();
        }
    }

    public final void setWidthMeasureSpec(int i) {
        this.c1 = i;
    }

    @Override // androidx.appcompat.widget.C0116w, android.widget.EditText, android.widget.TextView
    @NotNull
    public Editable getText() {
        Editable text = super.getText();
        Intrinsics.d(text);
        return text;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecText(Context context, AttributeSet attrs) throws Resources.NotFoundException {
        super(context, attrs, R.attr.editTextStyle);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
        kotlin.text.s sVar = kotlin.text.s.c;
        kotlin.text.s[] elements = {sVar, kotlin.text.s.b};
        Intrinsics.checkNotNullParameter(elements, "elements");
        this.g = new Regex(C4933y.T(elements));
        this.h = new Regex("^(?:[a-z]+:|#|\\?|\\.|/)", sVar);
        this.i = getResources().getBoolean(R.bool.history_enable);
        this.j = getResources().getInteger(R.integer.history_size);
        this.o = true;
        this.s = new byte[0];
        this.x = getResources().getBoolean(R.bool.comments_visible);
        this.y = true;
        this.B = true;
        this.D = -1;
        this.F = new ArrayList();
        this.W = new ArrayList();
        this.i1 = new org.wordpress.aztec.watchers.event.sequence.a(this);
        this.j1 = new org.wordpress.aztec.watchers.event.text.d();
        this.k1 = new androidx.camera.camera2.internal.concurrent.a(this);
        this.l1 = true;
        this.m1 = new C5147c();
        this.A = q1;
        k(attrs);
    }
}
