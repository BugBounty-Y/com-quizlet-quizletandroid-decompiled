package androidx.compose.ui.input.key;

import android.view.KeyEvent;
import androidx.compose.ui.q;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class c {
    public static final long a(int i) {
        long j = (i << 32) | (0 & 4294967295L);
        int i2 = a.o;
        return j;
    }

    public static final long b(KeyEvent keyEvent) {
        return a(keyEvent.getKeyCode());
    }

    public static final int c(KeyEvent keyEvent) {
        int action = keyEvent.getAction();
        if (action != 0) {
            return action != 1 ? 0 : 1;
        }
        return 2;
    }

    public static final q d(q qVar, Function1 function1) {
        return qVar.g(new KeyInputElement(function1, null));
    }

    public static final q e(q qVar, Function1 function1) {
        return qVar.g(new KeyInputElement(null, function1));
    }
}
