package androidx.compose.ui.autofill;

import android.view.autofill.AutofillManager;
import androidx.compose.ui.platform.C0971v;

/* loaded from: classes.dex */
public final class a implements b {
    public final C0971v a;
    public final f b;
    public final AutofillManager c;

    public a(C0971v c0971v, f fVar) {
        this.a = c0971v;
        this.b = fVar;
        AutofillManager autofillManager = (AutofillManager) c0971v.getContext().getSystemService(AutofillManager.class);
        if (autofillManager == null) {
            throw new IllegalStateException("Autofill service could not be located.");
        }
        this.c = autofillManager;
        c0971v.setImportantForAutofill(1);
    }
}
