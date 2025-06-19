package androidx.compose.ui.input.key;

import android.view.KeyEvent;
import androidx.compose.ui.p;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class e extends p implements d {
    public Function1 n;
    public Function1 o;

    @Override // androidx.compose.ui.input.key.d
    public final boolean B(KeyEvent keyEvent) {
        Function1 function1 = this.n;
        if (function1 != null) {
            return ((Boolean) function1.invoke(new b(keyEvent))).booleanValue();
        }
        return false;
    }

    @Override // androidx.compose.ui.input.key.d
    public final boolean k(KeyEvent keyEvent) {
        Function1 function1 = this.o;
        if (function1 != null) {
            return ((Boolean) function1.invoke(new b(keyEvent))).booleanValue();
        }
        return false;
    }
}
