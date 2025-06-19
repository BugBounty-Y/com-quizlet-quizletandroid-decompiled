package androidx.compose.ui.platform;

import android.view.View;
import androidx.compose.runtime.C0832v0;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class V0 implements View.OnAttachStateChangeListener {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    private final void a(View view) {
    }

    private final void b(View view) {
    }

    private final void c(View view) {
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewAttachedToWindow(View view) {
        switch (this.a) {
            case 0:
                AbstractC0930a abstractC0930a = (AbstractC0930a) this.b;
                androidx.lifecycle.J jF = androidx.lifecycle.p0.f(abstractC0930a);
                if (jF != null) {
                    ((kotlin.jvm.internal.J) this.c).a = N.o(abstractC0930a, jF.getLifecycle());
                    abstractC0930a.removeOnAttachStateChangeListener(this);
                    return;
                } else {
                    W4.g("View tree for " + abstractC0930a + " has no ViewTreeLifecycleOwner");
                    throw null;
                }
            case 1:
                return;
            case 2:
                ((View) this.b).removeOnAttachStateChangeListener(this);
                androidx.lifecycle.J jF2 = androidx.lifecycle.p0.f(view);
                if (jF2 != null) {
                    ((Function1) this.c).invoke(jF2);
                    return;
                }
                return;
            default:
                it.sephiroth.android.library.xtooltip.c cVar = (it.sephiroth.android.library.xtooltip.c) this.b;
                if (cVar != null) {
                    cVar.invoke(view, this);
                    return;
                }
                return;
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [kotlin.jvm.functions.Function2, kotlin.jvm.internal.r] */
    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewDetachedFromWindow(View view) {
        switch (this.a) {
            case 0:
                break;
            case 1:
                ((View) this.b).removeOnAttachStateChangeListener(this);
                ((C0832v0) this.c).w();
                break;
            case 2:
                break;
            default:
                ?? r0 = (kotlin.jvm.internal.r) this.c;
                if (r0 != 0) {
                    break;
                }
                break;
        }
    }

    public /* synthetic */ V0(View view, Object obj, int i) {
        this.a = i;
        this.b = view;
        this.c = obj;
    }
}
