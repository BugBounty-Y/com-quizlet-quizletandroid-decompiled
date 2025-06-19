package androidx.emoji2.text;

import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import androidx.lifecycle.C;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.quizletandroid.ui.library.G;
import com.quizlet.quizletandroid.ui.library.H;
import com.quizlet.quizletandroid.ui.library.InterfaceC4646d;
import com.quizlet.quizletandroid.ui.library.K;
import com.quizlet.quizletandroid.ui.library.c0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public final class k implements InterfaceC1250k {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ k(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onResume(J owner) {
        s0 s0Var;
        Object value;
        Object value2;
        switch (this.a) {
            case 0:
                (Build.VERSION.SDK_INT >= 28 ? AbstractC1120b.a(Looper.getMainLooper()) : new Handler(Looper.getMainLooper())).postDelayed(new n(0), 500L);
                ((C) this.b).b(this);
                break;
            case 1:
                Intrinsics.checkNotNullParameter(owner, "owner");
                Intrinsics.checkNotNullParameter(owner, "owner");
                c0 c0Var = (c0) ((InterfaceC4646d) this.b);
                c0Var.n.setScreenName("library");
                do {
                    s0Var = c0Var.t;
                    value = s0Var.getValue();
                } while (!s0Var.k(value, com.quizlet.quizletandroid.ui.library.data.J.a((com.quizlet.quizletandroid.ui.library.data.J) value, null, null, null, null, null, false, false, c0Var.q.isEnabled(), 127)));
                if (c0Var.s != null) {
                    do {
                        value2 = s0Var.getValue();
                    } while (!s0Var.k(value2, com.quizlet.quizletandroid.ui.library.data.J.a((com.quizlet.quizletandroid.ui.library.data.J) value2, null, c0Var.s, null, null, null, false, false, false, 253)));
                } else {
                    E.A(p0.j(c0Var), null, null, new H(c0Var, null), 3);
                }
                E.A(p0.j(c0Var), null, null, new com.quizlet.quizletandroid.ui.library.C(c0Var, false, false, null), 3);
                androidx.lifecycle.viewmodel.internal.a aVarJ = p0.j(c0Var);
                com.quizlet.quizletandroid.ui.library.J j = new com.quizlet.quizletandroid.ui.library.J(c0Var, null);
                C4203d c4203d = c0Var.z;
                E.A(aVarJ, c4203d, null, j, 2);
                E.A(p0.j(c0Var), c4203d, null, new com.quizlet.quizletandroid.ui.library.E(c0Var, null), 2);
                E.A(p0.j(c0Var), c4203d, null, new G(c0Var, null), 2);
                E.A(p0.j(c0Var), null, null, new K(c0Var, null), 3);
                break;
            default:
                Intrinsics.checkNotNullParameter(owner, "owner");
                ((Function0) this.b).invoke();
                break;
        }
    }

    public k(EmojiCompatInitializer emojiCompatInitializer, C c) {
        this.a = 0;
        this.b = c;
    }
}
