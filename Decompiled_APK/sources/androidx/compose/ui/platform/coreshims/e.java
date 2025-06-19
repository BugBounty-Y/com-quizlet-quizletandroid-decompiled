package androidx.compose.ui.platform.coreshims;

import android.view.View;
import android.view.autofill.AutofillId;

/* loaded from: classes.dex */
public abstract class e {
    public static AutofillId a(View view) {
        return view.getAutofillId();
    }
}
