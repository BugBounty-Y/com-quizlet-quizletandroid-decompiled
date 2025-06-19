package androidx.compose.ui.platform;

import android.content.Context;
import android.util.AttributeSet;
import androidx.compose.animation.C0281h;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class ComposeView extends AbstractC0930a {
    public static final /* synthetic */ int c = 0;
    public final InterfaceC0773a0 a;
    public boolean b;

    public ComposeView(@NotNull Context context) {
        this(context, null, 6);
    }

    public static /* synthetic */ void getShouldCreateCompositionOnAttachedToWindow$annotations() {
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public final void Content(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(420213850);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            Function2 function2 = (Function2) ((androidx.compose.runtime.L0) this.a).getValue();
            if (function2 == null) {
                c0814p.X(358373017);
            } else {
                c0814p.X(150107752);
                function2.invoke(c0814p, 0);
            }
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0281h(this, i, 29);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    @NotNull
    public CharSequence getAccessibilityClassName() {
        return "androidx.compose.ui.platform.ComposeView";
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public boolean getShouldCreateCompositionOnAttachedToWindow() {
        return this.b;
    }

    public final void setContent(@NotNull Function2<? super InterfaceC0806l, ? super Integer, Unit> function2) {
        this.b = true;
        ((androidx.compose.runtime.L0) this.a).setValue(function2);
        if (isAttachedToWindow()) {
            createComposition();
        }
    }

    public ComposeView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
    }

    public ComposeView(Context context, AttributeSet attributeSet, int i) {
        super(context, (i & 2) != 0 ? null : attributeSet);
        this.a = C0776c.z(null);
    }
}
