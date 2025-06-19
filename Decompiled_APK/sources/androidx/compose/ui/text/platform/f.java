package androidx.compose.ui.text.platform;

import android.text.InputFilter;
import android.text.Selection;
import android.text.Spannable;
import android.widget.TextView;
import androidx.appcompat.app.L;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final class f extends androidx.emoji2.text.h {
    public final /* synthetic */ int a = 1;
    public final Object b;
    public final Object c;

    public f(TextView textView, androidx.emoji2.viewsintegration.c cVar) {
        this.b = new WeakReference(textView);
        this.c = new WeakReference(cVar);
    }

    @Override // androidx.emoji2.text.h
    public void a() {
        switch (this.a) {
            case 0:
                ((L) this.c).b = i.a;
                break;
        }
    }

    @Override // androidx.emoji2.text.h
    public final void b() throws Throwable {
        InputFilter[] filters;
        int length;
        switch (this.a) {
            case 0:
                ((L0) ((InterfaceC0773a0) this.b)).setValue(Boolean.TRUE);
                ((L) this.c).b = new j(true);
                break;
            default:
                TextView textView = (TextView) ((WeakReference) this.b).get();
                InputFilter inputFilter = (InputFilter) ((WeakReference) this.c).get();
                if (inputFilter != null && textView != null && (filters = textView.getFilters()) != null) {
                    for (InputFilter inputFilter2 : filters) {
                        if (inputFilter2 == inputFilter) {
                            if (textView.isAttachedToWindow()) {
                                CharSequence text = textView.getText();
                                androidx.emoji2.text.j jVarA = androidx.emoji2.text.j.a();
                                if (text == null) {
                                    length = 0;
                                } else {
                                    jVarA.getClass();
                                    length = text.length();
                                }
                                CharSequence charSequenceF = jVarA.f(0, length, 0, text);
                                if (text != charSequenceF) {
                                    int selectionStart = Selection.getSelectionStart(charSequenceF);
                                    int selectionEnd = Selection.getSelectionEnd(charSequenceF);
                                    textView.setText(charSequenceF);
                                    if (charSequenceF instanceof Spannable) {
                                        Spannable spannable = (Spannable) charSequenceF;
                                        if (selectionStart < 0 || selectionEnd < 0) {
                                            if (selectionStart >= 0) {
                                                Selection.setSelection(spannable, selectionStart);
                                                break;
                                            } else if (selectionEnd >= 0) {
                                                Selection.setSelection(spannable, selectionEnd);
                                                break;
                                            }
                                        } else {
                                            Selection.setSelection(spannable, selectionStart, selectionEnd);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
                break;
        }
    }

    public f(InterfaceC0773a0 interfaceC0773a0, L l) {
        this.b = interfaceC0773a0;
        this.c = l;
    }
}
