package androidx.compose.ui.platform;

import androidx.compose.animation.core.C0242g;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.lang.reflect.Method;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.ui.platform.v0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0972v0 implements kotlin.coroutines.l, W0 {
    public static final /* synthetic */ C0972v0 a = new C0972v0();
    public static final C0972v0 b = new C0972v0();
    public static final g1 c = new g1();

    public static final boolean b() throws ClassNotFoundException {
        Class cls = C0971v.J1;
        try {
            if (C0971v.J1 == null) {
                Class<?> cls2 = Class.forName("android.os.SystemProperties");
                C0971v.J1 = cls2;
                C0971v.K1 = cls2.getDeclaredMethod("getBoolean", String.class, Boolean.TYPE);
            }
            Method method = C0971v.K1;
            Object objInvoke = method != null ? method.invoke(null, "debug.layout", Boolean.FALSE) : null;
            Boolean bool = objInvoke instanceof Boolean ? (Boolean) objInvoke : null;
            if (bool != null) {
                return bool.booleanValue();
            }
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    @Override // androidx.compose.ui.platform.W0
    public Function0 a(AbstractC0930a abstractC0930a) {
        if (!abstractC0930a.isAttachedToWindow()) {
            kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
            V0 v0 = new V0(abstractC0930a, j, 0);
            abstractC0930a.addOnAttachStateChangeListener(v0);
            j.a = new C0242g(26, abstractC0930a, v0);
            return new androidx.compose.ui.input.nestedscroll.b(j, 10);
        }
        androidx.lifecycle.J jF = androidx.lifecycle.p0.f(abstractC0930a);
        if (jF != null) {
            return N.o(abstractC0930a, jF.getLifecycle());
        }
        W4.g("View tree for " + abstractC0930a + " has no ViewTreeLifecycleOwner");
        throw null;
    }
}
