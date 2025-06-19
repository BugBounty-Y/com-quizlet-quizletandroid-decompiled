package androidx.compose.ui.platform;

import androidx.compose.foundation.gestures.C0346q0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;

/* renamed from: androidx.compose.ui.platform.m0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0955m0 {
    public static final androidx.compose.runtime.X0 a = new androidx.compose.runtime.X0(O.i);
    public static final androidx.compose.runtime.X0 b = new androidx.compose.runtime.X0(O.j);
    public static final androidx.compose.runtime.X0 c = new androidx.compose.runtime.X0(O.k);
    public static final androidx.compose.runtime.X0 d = new androidx.compose.runtime.X0(O.l);
    public static final androidx.compose.runtime.X0 e = new androidx.compose.runtime.X0(O.q);
    public static final androidx.compose.runtime.X0 f = new androidx.compose.runtime.X0(O.m);
    public static final androidx.compose.runtime.X0 g = new androidx.compose.runtime.X0(O.n);
    public static final androidx.compose.runtime.X0 h = new androidx.compose.runtime.X0(O.p);
    public static final androidx.compose.runtime.X0 i = new androidx.compose.runtime.X0(O.o);
    public static final androidx.compose.runtime.X0 j = new androidx.compose.runtime.X0(O.r);
    public static final androidx.compose.runtime.X0 k = new androidx.compose.runtime.X0(O.s);
    public static final androidx.compose.runtime.X0 l = new androidx.compose.runtime.X0(O.t);
    public static final androidx.compose.runtime.X0 m = new androidx.compose.runtime.X0(O.x);
    public static final androidx.compose.runtime.X0 n = new androidx.compose.runtime.X0(O.w);
    public static final androidx.compose.runtime.X0 o = new androidx.compose.runtime.X0(O.y);
    public static final androidx.compose.runtime.X0 p = new androidx.compose.runtime.X0(O.z);
    public static final androidx.compose.runtime.X0 q = new androidx.compose.runtime.X0(O.A);
    public static final androidx.compose.runtime.X0 r = new androidx.compose.runtime.X0(O.B);
    public static final androidx.compose.runtime.X0 s = new androidx.compose.runtime.X0(O.u);
    public static final androidx.compose.runtime.B t = new androidx.compose.runtime.B(O.v);

    public static final void a(androidx.compose.ui.node.g0 g0Var, C0935c0 c0935c0, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(874662829);
        int i3 = i2 | (c0814p.f(g0Var) ? 4 : 2) | (c0814p.f(c0935c0) ? 32 : 16) | (c0814p.h(dVar) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0971v c0971v = (C0971v) g0Var;
            C0811n0 c0811n0A = a.a(c0971v.getAccessibilityManager());
            C0811n0 c0811n0A2 = b.a(c0971v.getAutofill());
            C0811n0 c0811n0A3 = c.a(c0971v.getAutofillTree());
            C0811n0 c0811n0A4 = d.a(c0971v.m4getClipboardManager());
            C0811n0 c0811n0A5 = f.a(c0971v.getDensity());
            C0811n0 c0811n0A6 = g.a(c0971v.getFocusOwner());
            C0811n0 c0811n0A7 = h.a(c0971v.getFontLoader());
            c0811n0A7.f = false;
            C0811n0 c0811n0A8 = i.a(c0971v.getFontFamilyResolver());
            c0811n0A8.f = false;
            C0776c.b(new C0811n0[]{c0811n0A, c0811n0A2, c0811n0A3, c0811n0A4, c0811n0A5, c0811n0A6, c0811n0A7, c0811n0A8, j.a(c0971v.getHapticFeedBack()), k.a(c0971v.getInputModeManager()), l.a(c0971v.getLayoutDirection()), m.a(c0971v.getTextInputService()), n.a(c0971v.getSoftwareKeyboardController()), o.a(c0971v.getTextToolbar()), p.a(c0935c0), q.a(c0971v.getViewConfiguration()), r.a(c0971v.getWindowInfo()), s.a(c0971v.getPointerIconService()), e.a(c0971v.getGraphicsContext())}, dVar, c0814p, ((i3 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0346q0(i2, 8, g0Var, c0935c0, dVar);
        }
    }

    public static final void b(String str) {
        throw new IllegalStateException(("CompositionLocal " + str + " not present").toString());
    }
}
