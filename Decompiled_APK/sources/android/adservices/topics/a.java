package android.adservices.topics;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.internal.d;
import com.quizlet.features.questiontypes.written.ui.g;
import com.quizlet.quizletandroid.ui.widgets.ui.theme.b;
import com.quizlet.quizletandroid.ui.widgets.ui.theme.f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a {
    public static final /* synthetic */ int a = 0;

    public static final void a(d content, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(content, "content");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1989444597);
        if ((i & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0776c.b(new C0811n0[]{com.quizlet.quizletandroid.ui.widgets.ui.theme.a.a.a(new b(new com.quizlet.themes.b(false, 2), new com.quizlet.themes.b(true, 2))), f.a.a(com.quizlet.quizletandroid.ui.widgets.ui.theme.d.a)}, content, c0814p, 56);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new g(content, i, 1);
        }
    }

    public static void b(Parcel parcel, Parcelable parcelable) {
        if (parcelable == null) {
            parcel.writeInt(0);
        } else {
            parcel.writeInt(1);
            parcelable.writeToParcel(parcel, 0);
        }
    }
}
