package androidx.appcompat.widget;

import android.content.res.Resources;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import com.quizlet.explanations.feedback.ui.fragments.ReportThisContentFragment;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModePromptView;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.spans.AbstractC5167o;

/* loaded from: classes.dex */
public final class U0 implements TextWatcher {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ U0(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void a(Editable editable) {
    }

    private final void b(Editable editable) {
    }

    private final void c(Editable editable) {
    }

    private final void d(Editable editable) {
    }

    private final void e(int i, int i2, int i3, CharSequence charSequence) {
    }

    private final void f(int i, int i2, int i3, CharSequence charSequence) {
    }

    private final void g(int i, int i2, int i3, CharSequence charSequence) {
    }

    private final void h(int i, int i2, int i3, CharSequence charSequence) {
    }

    private final void i(int i, int i2, int i3, CharSequence charSequence) {
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable text) throws Resources.NotFoundException {
        boolean z = true;
        Object obj = this.b;
        switch (this.a) {
            case 0:
            case 1:
                break;
            case 2:
                if (text != null && text.length() != 0) {
                    z = false;
                }
                String str = ReportThisContentFragment.k;
                ReportThisContentFragment reportThisContentFragment = (ReportThisContentFragment) obj;
                ((com.quizlet.explanations.databinding.j) reportThisContentFragment.J()).d.setError(z ? reportThisContentFragment.getResources().getString(R.string.report_explanation_other_input_error) : null);
                break;
            case 3:
            case 4:
                break;
            default:
                Intrinsics.checkNotNullParameter(text, "text");
                AztecText aztecText = (AztecText) obj;
                aztecText.getContentChangeWatcher().a();
                if (!aztecText.m) {
                    Object[] spans = text.getSpans(0, text.length(), AbstractC5167o.class);
                    Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                    aztecText.setMediaAdded(!(spans.length == 0));
                    if (aztecText.getConsumeHistoryEvent()) {
                        aztecText.setConsumeHistoryEvent(false);
                        break;
                    }
                }
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence text, int i, int i2, int i3) {
        String string;
        switch (this.a) {
            case 0:
            case 1:
            case 2:
                break;
            case 3:
                if (text != null && (string = text.toString()) != null && string.length() > 0 && i3 < i2) {
                    int iQ = StringsKt.Q(string, " ", 0, 6);
                    if (iQ != -1) {
                        string = string.substring(iQ, string.length());
                        Intrinsics.checkNotNullExpressionValue(string, "substring(...)");
                    }
                    String description = StringsKt.g0(string).toString();
                    com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVar = (com.quizlet.quizletandroid.ui.setcreation.viewmodels.h) this.b;
                    Intrinsics.checkNotNullParameter(description, "description");
                    if ((hVar.q instanceof com.quizlet.scandocument.model.k) && hVar.C().contains(description)) {
                        hVar.I(string);
                        hVar.h.l(new com.quizlet.scandocument.model.e(string));
                        break;
                    }
                }
                break;
            case 4:
                break;
            default:
                Intrinsics.checkNotNullParameter(text, "text");
                AztecText aztecText = (AztecText) this.b;
                if (aztecText.u && !aztecText.m && !aztecText.getConsumeHistoryEvent()) {
                    aztecText.getHistory().a(aztecText);
                    break;
                }
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence text, int i, int i2, int i3) {
        switch (this.a) {
            case 0:
                SearchView searchView = (SearchView) this.b;
                Editable text2 = searchView.p.getText();
                searchView.l1 = text2;
                boolean zIsEmpty = TextUtils.isEmpty(text2);
                searchView.y(!zIsEmpty);
                int i4 = 8;
                if (searchView.j1 && !searchView.c1 && zIsEmpty) {
                    searchView.u.setVisibility(8);
                    i4 = 0;
                }
                searchView.w.setVisibility(i4);
                searchView.u();
                searchView.x();
                if (searchView.K != null && !TextUtils.equals(text, searchView.k1)) {
                    searchView.K.c(text.toString());
                }
                searchView.k1 = text.toString();
                break;
            case 1:
                ((com.google.android.material.search.SearchView) this.b).k.setVisibility(text.length() > 0 ? 0 : 8);
                break;
            case 2:
                break;
            case 3:
                ((com.quizlet.quizletandroid.ui.setcreation.viewmodels.h) this.b).h.l(com.quizlet.scandocument.model.f.a);
                break;
            case 4:
                WriteModePromptView writeModePromptView = (WriteModePromptView) this.b;
                if (!writeModePromptView.G) {
                    if (writeModePromptView.F) {
                        writeModePromptView.i.setVisibility(4);
                        writeModePromptView.j.setVisibility(text.length() > 0 ? 4 : 0);
                    } else {
                        writeModePromptView.i.setVisibility((text.length() > 0 || writeModePromptView.H) ? 4 : 0);
                        writeModePromptView.j.setVisibility(4);
                    }
                    if (writeModePromptView.E && text.length() > 0) {
                        writeModePromptView.h();
                        break;
                    }
                } else {
                    writeModePromptView.i();
                    writeModePromptView.C.c(false);
                    break;
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(text, "text");
                boolean z = ((AztecText) this.b).u;
                break;
        }
    }
}
